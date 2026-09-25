# DNS Ingress

> **v2 配置迁移：** 上游主机名始终由改写后的目标域名决定。请将旧的
> `upstream.default` 与各协议固定 URL/地址替换为按协议配置的端点参数；
> 旧固定上游配置会被拒绝。

[English](README.md)

DNS-Ingress 是一个 DNS 请求路由器，可以根据子域名前缀将查询转发到不同的上游服务器。例如：将 api.example.org 转发到 api.example.cn，将 www.example.org 转发到 www.example.cn。支持 DoT、DoH、DoQ、DoH3 协议。

## 功能特性

- ✅ **DoT (DNS over TLS)** - TCP 853 端口
- ✅ **DoH (DNS over HTTPS)** - TCP 443 端口
- ✅ **DoQ (DNS over QUIC)** - UDP 853 端口
- ✅ **DoH3 (DNS over HTTP/3)** - UDP 443 端口
- 🔒 **动态 TLS 证书选择** - 基于 SNI 自动选择证书
- 🎯 **多域名支持** - 支持多个基准域名的前缀提取和重写
- 🚀 **高性能** - 基于 Tokio 异步运行时，支持高并发
- ⚡ **零拷贝优化** - 减少不必要的内存复制，提升性能
- 🏗️ **模块化架构** - 清晰的模块划分，易于扩展和维护
- 📊 **性能监控** - 基于 Prometheus 的指标收集和导出
- 🏥 **健康检查** - HTTP 健康检查端点，支持 JSON 和 Prometheus 格式指标
- 📝 **日志系统** - 支持多级别日志、文件输出、JSON 格式和日志轮转

## 工作原理

### 整体架构

DNS Ingress Server 接收来自客户端的 DNS 查询请求，通过 Protocol Readers（DoH、DoT、DoQ、DoH3）处理不同协议的请求。系统从请求中提取 SNI（Server Name Indication），通过 SNI Rewriter 进行域名重写，然后使用 Certificate Resolver 根据 SNI 动态选择 TLS 证书，最后将请求转发到上游 DNS 服务器。同时，系统会收集性能指标并通过健康检查服务器提供监控接口。

### 工作流程详解

#### 1. 启动阶段

程序从 `main.rs` 开始，首先初始化 Rustls 加密提供者，然后加载配置文件（`config.toml` 或使用默认值）并验证配置，接着初始化日志系统，创建 `App` 实例（包括初始化 SNI Rewriter 和指标收集器），最后并行启动各个协议的服务器（DoT Server、DoH Server、DoQ Server、DoH3 Server）以及健康检查服务器。

#### 2. 请求处理流程（以 DoH 为例）

1. **客户端请求**：客户端发送 GET/POST 请求到 `https://www.example.org/dns-query`，请求头包含 `Host: www.example.org`

2. **DoH Server 接收**：服务器从 Host header 中提取 SNI 信息（"www.example.org"），然后调用 SNI Rewriter

3. **SNI Rewriter 处理**：重写器匹配基准域名列表（如 `["example.com", "example.org"]`），找到匹配项后提取前缀（"www"），构建目标主机名（"www.example.cn"），并缓存映射关系

4. **转发请求**：构建上游 URI（`https://www.example.cn/dns-query`），复制并更新请求头中的 Host，转发到上游服务器，最后将响应返回给客户端

#### 3. SNI 重写逻辑

**前缀提取算法：**

```rust
输入: SNI = "www.example.org"
配置: base_domains = ["example.com", "example.org"]
      target_suffix = ".example.cn"

步骤:
1. 遍历 base_domains
2. 检查 SNI 是否以 base_domain 结尾
   - "www.example.org".ends_with("example.org") ✓
3. 提取剩余部分
   - rest = "www.example.org".strip_suffix("example.org") = "www."
4. 验证格式（必须以 '.' 结尾且不为空）
   - rest.ends_with('.') && !rest.is_empty() ✓
5. 提取前缀
   - prefix = "www.".strip_suffix('.') = "www"
6. 构建目标主机名
   - target = prefix + target_suffix = "www.example.cn"
```

**示例：**

| 输入 SNI          | 匹配基准域名  | 提取前缀 | 目标主机名                 |
| ----------------- | ------------- | -------- | -------------------------- |
| `www.example.org` | `example.org` | `www`    | `www.example.cn`           |
| `api.example.com` | `example.com` | `api`    | `api.example.cn`           |
| `sub.example.org` | `example.org` | `sub`    | `sub.example.cn`           |
| `example.org`     | -             | -        | 不匹配（无前缀）           |
| `www.other.com`   | -             | -        | 不匹配（不在基准域名列表） |

#### 4. TLS 证书选择

当收到 TLS 握手请求（SNI: www.example.org）时，`CertificateResolver.resolve()` 首先检查证书缓存。如果缓存命中，直接返回缓存的证书。如果未命中，则查找证书配置：先查找精确匹配的 `tls.certs["www.example.org"]`，如果未找到则查找基准域名 `tls.certs["example.org"]`，如果仍未找到则回退到 `tls.default`。找到配置后加载证书文件，缓存并返回。

**证书选择优先级：**

1. **精确匹配** - `tls.certs[SNI]`（例如：`tls.certs["www.example.org"]`）
2. **基准域名匹配** - `tls.certs[base_domain]`（例如：`tls.certs["example.org"]`）
3. **默认证书** - `tls.default`（如果配置）
4. **错误** - 如果没有找到任何证书配置

#### 5. 各协议实现细节

**DoH (DNS over HTTPS)**

- 监听端口：TCP 443
- SNI 提取：从 HTTP `Host` header
- 请求转发：使用 Hyper HTTP 客户端
- 支持方法：GET、POST

**DoT (DNS over TLS)**

- 监听端口：TCP 853
- SNI 提取：从 TLS handshake（通过 `ClientHello`）
- 请求转发：TLS 隧道转发
- 证书选择：动态证书解析器

**DoQ (DNS over QUIC)**

- 监听端口：UDP 853
- SNI 提取：从 QUIC connection
- 请求转发：QUIC 双向流转发
- 实现：使用 quinn 0.11 和模块化的 QUIC 客户端

**DoH3 (DNS over HTTP/3)**

- 监听端口：UDP 443
- SNI 提取：从 HTTP Host header
- 请求转发：HTTP/3 请求转发（使用 h3 和 h3-quinn）
- 实现：完整的 HTTP/3 服务器和客户端支持

## 项目架构

### 目录结构

```
src/
├── main.rs              # 程序入口，初始化日志和配置
├── app.rs               # 应用生命周期管理，启动各协议服务器
├── config.rs            # 配置结构定义和加载逻辑
├── server.rs            # 服务器启动工具和共享资源
├── metrics.rs           # Prometheus 指标收集和导出
├── logging.rs           # 日志系统初始化
├── sni.rs               # SNI 重写器 trait 定义
├── rewrite.rs           # Rewriter 工厂函数
├── tls_utils.rs         # TLS 证书加载和动态选择
├── utils.rs             # 工具函数
├── quic/                # QUIC 相关模块
│   ├── mod.rs          # 模块导出
│   ├── config.rs       # QUIC 服务器配置
│   └── client.rs       # QUIC 客户端连接
├── upstream/            # 上游连接模块
│   ├── mod.rs          # 模块导出
│   ├── http.rs         # HTTP 客户端和转发
│   ├── quic.rs         # QUIC 流转发
│   └── pool.rs         # 连接池管理
├── proxy/               # 代理转发模块
│   ├── mod.rs          # 模块导出
│   └── http.rs         # HTTP 请求处理和 SNI 重写
├── readers/             # 协议服务器实现
│   ├── mod.rs          # 模块导出
│   ├── doh.rs          # DoH 服务器实现
│   ├── dot.rs          # DoT 服务器实现
│   ├── doq.rs          # DoQ 服务器实现
│   ├── doh3.rs         # DoH3 服务器实现
│   └── healthcheck.rs  # 健康检查服务器
└── rewriters/          # SNI 重写器实现
    ├── mod.rs          # 模块导出
    └── base.rs         # 基础前缀提取重写器

tests/                   # 测试用例
├── config.rs           # 配置模块测试
├── rewriters_base.rs   # 重写器测试
├── rewrite.rs          # 工厂函数测试
├── tls_utils.rs        # TLS 工具测试
├── app.rs              # 应用测试
├── quic.rs             # QUIC 模块测试
├── upstream.rs         # 上游模块测试
├── proxy.rs            # 代理模块测试
├── metrics.rs          # 指标模块测试
└── performance.rs      # 性能测试
```

### 核心模块说明

#### `sni.rs` - SNI 重写器接口

定义了 `SniRewriter` trait，所有重写器必须实现：

```rust
pub trait SniRewriter {
    async fn rewrite(&self, sni: &str) -> Option<RewriteResult>;
}
```

#### `rewriters/base.rs` - 基础重写器

实现了前缀提取和重写逻辑：

- 支持多个基准域名
- 前缀提取算法
- 目标主机名构建
- SNI 映射缓存

#### `quic/` - QUIC 模块

QUIC 相关的配置和连接管理：

- `config.rs` - 统一的 QUIC 服务器端点创建
- `client.rs` - QUIC 客户端连接管理

#### `upstream/` - 上游连接模块

上游服务器的连接和转发逻辑：

- `http.rs` - HTTP 客户端创建和请求转发（共享客户端实例）
- `quic.rs` - QUIC 流转发（零拷贝优化）

#### `proxy/` - 代理转发模块

代理转发逻辑的抽象：

- `http.rs` - HTTP 请求处理、SNI 重写和上游转发

#### `readers/` - 协议服务器

每个协议独立的服务器实现（已简化，使用共享模块）：

- 监听指定端口
- 使用 `proxy` 模块处理请求
- 使用 `upstream` 模块转发到上游

#### `tls_utils.rs` - TLS 证书管理

- 动态证书加载
- 基于 SNI 的证书选择
- 证书缓存机制
- 锁中毒检测

#### `metrics.rs` - 性能监控

- Prometheus 指标收集
- 请求统计（总数、成功、失败）
- 流量统计（接收、发送字节数）
- SNI 重写统计
- 上游错误统计
- 处理时间直方图
- 指标快照缓存（减少锁竞争）
- 支持 Prometheus 文本格式和 JSON 格式导出

#### `server.rs` - 服务器工具

- 统一的服务器启动接口
- 共享资源管理（配置、重写器、指标）
- 优雅关闭支持

#### `readers/healthcheck.rs` - 健康检查服务器

- HTTP 健康检查端点
- Prometheus 指标导出（`/metrics` 或 `/stats`）
- JSON 格式指标导出（`/metrics/json`）
- 可配置的检查路径

#### `app.rs` - 应用管理

- 配置加载和验证
- 重写器创建
- 指标收集器初始化
- 各协议服务器启动（并行）
- 健康检查服务器启动
- 生命周期管理

## 配置说明

### 配置文件格式

复制 `config.toml.example` 为 `config.toml` 并根据需要修改：

```toml
[rewrite]
# 基准域名列表，支持多个域名
# 重写器会从匹配这些基准域名的 hostname 中提取前缀
base_domains = ["example.com", "example.org"]
# 目标域名后缀，提取的前缀会与此后缀组合形成目标主机名
target_suffix = ".example.cn"

[servers]
# DNS over TLS (DoT) - TCP 853
[servers.dot]
enabled = true
bind_address = "0.0.0.0"
port = 853

# DNS over HTTPS (DoH) - TCP 443
[servers.doh]
enabled = true
bind_address = "0.0.0.0"
port = 443
path = "/dns-query"

# DNS over QUIC (DoQ) - UDP 853
[servers.doq]
enabled = true
bind_address = "0.0.0.0"
port = 853

# DNS over HTTP/3 (DoH3) - UDP 443
[servers.doh3]
enabled = false
bind_address = "0.0.0.0"
port = 443
path = "/dns-query"

# Healthcheck server - HTTP endpoint for health checks
[servers.healthcheck]
enabled = true
bind_address = "0.0.0.0"
port = 8080
path = "/health"

[upstream]
[upstream.dot]
port = 853
[upstream.doh]
port = 443
path = "/dns-query"
[upstream.doq]
port = 853
[upstream.doh3]
port = 443
path = "/dns-query"

[limits]
# 每个公开 listener 的并发连接数上限
max_connections_per_listener = 1024
# HTTP/2、HTTP/3、DoQ 单连接并发 DNS 请求上限
max_inflight_requests_per_connection = 64
# 以重写后的 authority 为键的上游连接池上限
max_upstream_pool_entries = 256
# 单次请求无 I/O 进展的超时（持续流式 AXFR/IXFR 不受总时长限制）
transaction_timeout_seconds = 30

[tls]
# 可选：验证私有 PKI 重写上游时追加的 PEM 根证书包。
# 它只影响出站信任，不启用入站 mTLS。
# upstream_ca_file = "/path/to/private-upstream-ca.pem"
# 默认证书配置（可选，当没有找到域名特定证书时使用）
[tls.default]
cert_file = "/path/to/default-cert.pem"
key_file = "/path/to/default-key.pem"

# 为每个基准域名配置独立的证书
[tls.certs.example.com]
cert_file = "/path/to/example-com-cert.pem"
key_file = "/path/to/example-com-key.pem"

[tls.certs.example.org]
cert_file = "/path/to/example-org-cert.pem"
key_file = "/path/to/example-org-key.pem"
```

### 配置项说明

#### `[rewrite]` - 重写配置

- **`base_domains`** (必需): 基准域名列表，用于匹配和提取前缀
- **`target_suffix`** (必需): 目标域名后缀，与提取的前缀组合

#### `[limits]` - 资源限制

`max_connections_per_listener` 限制所有公开 listener 的连接数；in-flight
限制适用于可多路复用的 DoH、DoQ、DoH3 请求流。上游池按重写后的
authority 与协议建立键；DoQ 与 DoH3 会复用 QUIC 会话。
`transaction_timeout_seconds` 是无 I/O 进展超时，不是 AXFR/IXFR 的总时长限制。

#### `[servers.*]` - 服务器配置

每个协议服务器配置：

- **`enabled`**: 是否启用该协议服务器
- **`bind_address`**: 绑定地址（如 "0.0.0.0" 或 "127.0.0.1"）
- **`port`**: 监听端口

健康检查服务器配置（`[servers.healthcheck]`）：

- **`enabled`**: 是否启用健康检查服务器
- **`bind_address`**: 绑定地址
- **`port`**: 监听端口（默认：8080）
- **`path`**: 健康检查路径（默认：`/health`）

健康检查服务器提供以下端点：

- `GET /health` - 返回服务健康状态（JSON 格式）
- `GET /metrics` 或 `GET /stats` - 返回 Prometheus 格式指标
- `GET /metrics/json` - 返回 JSON 格式指标

#### `[upstream]` - 上游端点配置

上游主机名由重写器生成；`dot`、`doq` 配置 `port`，`doh`、`doh3`
配置 `port` 与 `path`。不再支持固定上游主机，以避免绕过域名路由。

#### `[tls]` - TLS 证书配置

- **`[tls.default]`**: 默认证书配置（可选）
- **`[tls.certs.<domain>]`**: 域名特定的证书配置
  - **`cert_file`**: 证书文件路径（PEM 格式）
  - **`key_file`**: 私钥文件路径（PEM 格式）
- **`upstream_ca_file`**: 可选 PEM 根证书包；验证重写后的私有 PKI 上游时
  追加到公共根证书，且不配置客户端认证。应用启动时加载一次；轮换后需要重启。

#### `[logging]` - 日志配置

- **`level`**: 日志级别，可选值：`trace`, `debug`, `info`, `warn`, `error`（默认：`info`）
  - 也可以通过环境变量 `RUST_LOG` 设置，环境变量优先级更高
- **`file`**: 日志文件路径（可选，如果未设置，日志仅输出到 stdout/stderr）
- **`json`**: 是否启用 JSON 格式日志（默认：`false`）
  - JSON 格式便于后续分析和日志聚合工具处理
- **`rotation`**: 是否启用日志轮转（默认：`true`，仅在设置了 `file` 时生效）
- **`max_file_size`**: 日志文件最大大小（字节），超过后轮转（默认：10485760，即 10MB）
- **`max_files`**: 保留的日志文件数量（默认：`5`）

**日志配置示例：**

```toml
[logging]
level = "info"
file = "/var/log/dns-ingress/dns-ingress.log"
json = false
rotation = true
max_file_size = 10485760  # 10MB
max_files = 5
```

**日志功能特性：**

- ✅ 支持多级别日志（trace, debug, info, warn, error）
- ✅ 支持文件输出和标准输出同时记录
- ✅ 支持 JSON 格式日志（便于日志分析工具处理）
- ✅ 支持日志轮转（按天或按大小）
- ✅ 详细的错误上下文信息
- ✅ 结构化日志记录（包含文件、行号、时间戳等）

## 使用方法

### 编译

```bash
# 开发模式
cargo build

# 发布模式
cargo build --release
```

### 运行

```bash
# 使用默认配置（从 config.toml 加载，如果不存在则使用默认值）
cargo run

# 或直接运行编译后的二进制文件
./target/release/dns-ingress
```

### 测试

```bash
# 运行所有测试
cargo test

# 运行特定测试套件
cargo test --test config
cargo test --test quic
cargo test --test upstream
cargo test --test proxy
cargo test --test metrics

# 运行单元测试
cargo test --lib

# 显示测试输出
cargo test -- --nocapture
```

### 监控和健康检查

启动服务后，可以通过健康检查端点监控服务状态：

```bash
# 检查进程存活和全部 listener 就绪状态
curl http://localhost:8080/live
curl http://localhost:8080/ready

# 自定义兼容检查路径（默认 /health）
curl http://localhost:8080/health

# 获取 Prometheus 格式指标
curl http://localhost:8080/metrics

# 获取 JSON 格式指标
curl http://localhost:8080/metrics/json
```

健康检查端点返回的指标包括：

- 总请求数
- 成功/失败请求数
- 接收/发送字节数
- SNI 重写次数
- 上游错误数
- 平均处理时间
- 成功率
- 吞吐量（请求/秒）

## 扩展性

### 添加新的协议支持

要添加新的协议支持，请参考 `src/readers/README.md`：

1. 在 `readers/` 目录下创建新的协议文件（如 `new_protocol.rs`）
2. 实现服务器结构体和 `start()` 方法
3. 在 `readers/mod.rs` 中导出
4. 在 `app.rs` 中添加启动逻辑

### 添加新的重写器

要添加自定义的 SNI 重写逻辑，请参考 `src/rewriters/README.md`：

1. 在 `rewriters/` 目录下创建新的重写器文件
2. 实现 `SniRewriter` trait
3. 在 `rewriters/mod.rs` 中导出
4. 在 `rewrite.rs` 中更新工厂函数（可选）

## 性能优化

项目采用了多项性能优化措施：

1. **共享配置** - 使用 `Arc<AppConfig>` 避免配置复制
2. **证书缓存** - TLS 证书加载后缓存，避免重复文件 I/O
3. **SNI 映射缓存** - 重写结果缓存，提高查询速度
4. **异步 I/O** - 基于 Tokio 的异步运行时，支持高并发
5. **零拷贝优化** - 减少不必要的内存复制：
   - 使用 `Bytes` 和切片引用而非 `Vec<u8>` 复制
   - 复用缓冲区（如 DoT reader 中复用 buffer）
   - 直接使用 `to_bytes()` 而非额外复制
   - 使用切片引用传递数据（`&[u8]` 而非 `Vec<u8>`）
6. **共享客户端实例** - HTTP 客户端在服务器实例间共享，避免重复创建
7. **指标快照缓存** - 指标快照缓存 1 秒，减少锁竞争和重复计算
8. **批量指标更新** - 使用 `record_request()` 批量更新多个指标，减少原子操作次数
9. **模块化设计** - 清晰的模块划分，减少代码重复，提高可维护性
10. **连接池管理** - 上游连接池复用，减少连接建立开销

## 待完善功能

- [ ] TLS 证书动态加载和热重载
- [x] 更完善的错误处理和日志记录
- [x] 性能监控和统计
- [ ] 配置热重载
- [ ] 请求限流和速率限制
- [ ] 更细粒度的指标标签（按协议、域名等）

## 依赖

### 核心依赖

- `tokio` - 异步运行时
- `rustls` / `tokio-rustls` - TLS 支持
- `quinn` (0.11) - QUIC 协议支持
- `h3` (0.0.8) / `h3-quinn` (0.0.10) - HTTP/3 支持
- `hyper` / `hyper-util` - HTTP 支持
- `rustls-native-certs` - 系统根证书支持

### 工具依赖

- `serde` / `toml` - 配置解析
- `tracing` / `tracing-subscriber` - 日志记录（支持 JSON 格式和日志轮转）
- `tracing-appender` - 日志文件输出和轮转
- `anyhow` - 错误处理（提供详细的错误上下文）
- `thiserror` - 错误类型定义
- `bytes` - 字节处理（零拷贝优化）
- `http-body-util` - HTTP body 工具
- `async-trait` - 异步 trait 支持
- `futures` - Future 工具
- `prometheus` - Prometheus 指标收集和导出
- `dashmap` - 并发哈希表（用于 SNI 映射缓存）

### 开发依赖

- `tempfile` - 临时文件（测试用）
- `reqwest` - HTTP 客户端（测试用）
- `tokio-test` - Tokio 测试工具

## 许可证

AGPL3
