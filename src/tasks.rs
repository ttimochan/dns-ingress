use futures::future::BoxFuture;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinSet;

enum Command {
    Spawn(BoxFuture<'static, ()>),
    Shutdown {
        deadline: tokio::time::Instant,
        completed: oneshot::Sender<()>,
    },
}

/// A listener-local task supervisor. Its actor is the sole JoinSet owner, so
/// child tasks may spawn descendants while shutdown waits without lock cycles.
#[derive(Clone)]
pub struct TaskGroup {
    state: Arc<Mutex<TaskGroupState>>,
}

struct TaskGroupState {
    closed: bool,
    commands: Option<mpsc::UnboundedSender<Command>>,
}

impl Default for TaskGroup {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(TaskGroupState {
                closed: false,
                commands: None,
            })),
        }
    }
}

impl TaskGroup {
    async fn spawn_command(&self, task: BoxFuture<'static, ()>) {
        // The state lock orders Spawn before Shutdown.  In particular, a
        // sender obtained before close_and_wait_until cannot enqueue work
        // behind the shutdown command after the group has been closed.
        let mut state = self.state.lock().await;
        if state.closed {
            return;
        }
        if state.commands.is_none() {
            let (sender, receiver) = mpsc::unbounded_channel();
            Self::start_supervisor(receiver);
            state.commands = Some(sender);
        }
        if let Some(commands) = &state.commands {
            let _ = commands.send(Command::Spawn(task));
        }
    }

    fn start_supervisor(mut receiver: mpsc::UnboundedReceiver<Command>) {
        tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                let command = tokio::select! {
                    command = receiver.recv() => command,
                    _ = tasks.join_next(), if !tasks.is_empty() => continue,
                };
                let Some(command) = command else { break };
                match command {
                    Command::Spawn(task) => {
                        tasks.spawn(task);
                    }
                    Command::Shutdown {
                        deadline,
                        completed,
                    } => {
                        receiver.close();
                        while !tasks.is_empty() {
                            if tokio::time::timeout_at(deadline, tasks.join_next())
                                .await
                                .is_err()
                            {
                                tasks.abort_all();
                                while tasks.join_next().await.is_some() {}
                                break;
                            }
                        }
                        let _ = completed.send(());
                        break;
                    }
                }
            }
        });
    }
    pub async fn spawn<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.spawn_command(Box::pin(future)).await;
    }

    pub async fn close_and_wait_until(&self, deadline: tokio::time::Instant) {
        let commands = {
            let mut state = self.state.lock().await;
            if state.closed {
                return;
            }
            state.closed = true;
            state.commands.clone()
        };
        let Some(commands) = commands else {
            return;
        };
        let (completed, receiver) = oneshot::channel();
        if commands
            .send(Command::Shutdown {
                deadline,
                completed,
            })
            .is_ok()
        {
            let _ = receiver.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TaskGroup;
    use tokio::sync::oneshot;

    struct DropSignal(Option<oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    #[tokio::test]
    async fn shutdown_aborts_children_that_ignore_cancellation() {
        let tasks = TaskGroup::default();
        let (dropped, receiver) = oneshot::channel();
        tasks
            .spawn(async move {
                let _signal = DropSignal(Some(dropped));
                std::future::pending::<()>().await;
            })
            .await;
        tokio::task::yield_now().await;

        tasks
            .close_and_wait_until(
                tokio::time::Instant::now() + std::time::Duration::from_millis(20),
            )
            .await;
        tokio::time::timeout(std::time::Duration::from_secs(1), receiver)
            .await
            .expect("aborted child was not dropped")
            .expect("drop signal sender disappeared");
    }

    #[tokio::test]
    async fn spawn_after_close_is_dropped_without_running() {
        let tasks = TaskGroup::default();
        tasks
            .close_and_wait_until(tokio::time::Instant::now())
            .await;
        let (dropped, receiver) = oneshot::channel();
        let signal = DropSignal(Some(dropped));
        tasks
            .spawn(async move {
                let _signal = signal;
                std::future::pending::<()>().await;
            })
            .await;
        tokio::time::timeout(std::time::Duration::from_secs(1), receiver)
            .await
            .expect("rejected task was not dropped")
            .expect("drop signal sender disappeared");
    }
}
