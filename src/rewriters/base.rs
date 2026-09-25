use crate::config::RewriteConfig;
use crate::sni::{RewriteResult, SniRewriter};
use tracing::{info, warn};

pub struct BaseSniRewriter {
    config: RewriteConfig,
}

impl BaseSniRewriter {
    pub fn new(mut config: RewriteConfig) -> Self {
        for domain in &mut config.base_domains {
            *domain = domain.trim_end_matches('.').to_ascii_lowercase();
        }
        config.target_suffix = config.target_suffix.to_ascii_lowercase();
        Self { config }
    }

    pub fn extract_prefix(&self, sni: &str) -> Option<String> {
        for base_domain in &self.config.base_domains {
            if let Some(rest) = sni.strip_suffix(base_domain)
                && !rest.is_empty()
                && rest.ends_with('.')
            {
                let prefix = rest.strip_suffix('.').unwrap_or(rest);
                if !prefix.is_empty() {
                    return Some(prefix.to_string());
                }
            }
        }
        None
    }

    pub fn build_target_hostname(&self, prefix: &str) -> String {
        format!("{}{}", prefix, self.config.target_suffix)
    }
}

#[async_trait::async_trait]
impl SniRewriter for BaseSniRewriter {
    async fn rewrite(&self, sni: &str) -> Option<RewriteResult> {
        // Validate input
        if sni.is_empty() {
            warn!("Empty SNI provided for rewrite");
            return None;
        }

        // Check if base domains are configured
        if self.config.base_domains.is_empty() {
            warn!("No base domains configured for SNI rewriting");
            return None;
        }

        // Validate target suffix
        if !self.config.target_suffix.starts_with('.') {
            warn!(
                "Invalid target suffix: {} (must start with '.')",
                self.config.target_suffix
            );
            return None;
        }

        let normalized = sni.trim_end_matches('.').to_ascii_lowercase();
        if !normalized.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-'
        }) {
            warn!("Invalid non-ASCII DNS hostname provided for rewrite");
            return None;
        }

        // DNS hostnames are ASCII case-insensitive. Config validation keeps
        // base domains canonical, so matching is deterministic here.
        let prefix = match self.extract_prefix(&normalized) {
            Some(p) => p,
            None => return None,
        };

        let target_hostname = self.build_target_hostname(&prefix);

        info!(
            "SNI Rewrite: {} -> Prefix: {} -> Target: {}",
            normalized, prefix, target_hostname
        );

        Some(RewriteResult {
            original: normalized,
            prefix,
            target_hostname,
        })
    }
}

#[async_trait::async_trait]
impl SniRewriter for std::sync::Arc<BaseSniRewriter> {
    async fn rewrite(&self, sni: &str) -> Option<RewriteResult> {
        self.as_ref().rewrite(sni).await
    }
}
