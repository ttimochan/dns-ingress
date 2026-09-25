use dns_ingress::config::RewriteConfig;
use dns_ingress::rewriters::base::BaseSniRewriter;
use dns_ingress::sni::SniRewriter;
use std::sync::Arc;

fn create_test_config() -> RewriteConfig {
    RewriteConfig {
        base_domains: vec!["example.com".to_string(), "example.org".to_string()],
        target_suffix: ".example.cn".to_string(),
    }
}

#[tokio::test]
async fn test_extract_prefix_with_prefix() {
    let config = create_test_config();
    let rewriter = BaseSniRewriter::new(config);

    assert_eq!(
        rewriter.extract_prefix("www.example.org"),
        Some("www".to_string())
    );
    assert_eq!(
        rewriter.extract_prefix("api.example.com"),
        Some("api".to_string())
    );
    assert_eq!(
        rewriter.extract_prefix("subdomain.example.org"),
        Some("subdomain".to_string())
    );
}

#[tokio::test]
async fn test_extract_prefix_without_prefix() {
    let config = create_test_config();
    let rewriter = BaseSniRewriter::new(config);

    assert_eq!(rewriter.extract_prefix("example.org"), None);
    assert_eq!(rewriter.extract_prefix("example.com"), None);
}

#[tokio::test]
async fn test_extract_prefix_unknown_domain() {
    let config = create_test_config();
    let rewriter = BaseSniRewriter::new(config);

    assert_eq!(rewriter.extract_prefix("www.unknown.com"), None);
    assert_eq!(rewriter.extract_prefix("test.net"), None);
}

#[tokio::test]
async fn test_build_target_hostname() {
    let config = create_test_config();
    let rewriter = BaseSniRewriter::new(config);

    assert_eq!(
        rewriter.build_target_hostname("www"),
        "www.example.cn".to_string()
    );
    assert_eq!(
        rewriter.build_target_hostname("api"),
        "api.example.cn".to_string()
    );
}

#[tokio::test]
async fn test_rewrite_sni() {
    let config = create_test_config();
    let rewriter = BaseSniRewriter::new(config);

    let result = rewriter.rewrite("www.example.org").await;
    assert!(result.is_some());
    let result = result.unwrap();
    assert_eq!(result.original, "www.example.org");
    assert_eq!(result.prefix, "www");
    assert_eq!(result.target_hostname, "www.example.cn");
}

#[tokio::test]
async fn test_rewrite_sni_multiple_domains() {
    let config = create_test_config();
    let rewriter = BaseSniRewriter::new(config);

    let result1 = rewriter.rewrite("www.example.org").await;
    assert!(result1.is_some());
    assert_eq!(result1.unwrap().target_hostname, "www.example.cn");

    let result2 = rewriter.rewrite("api.example.com").await;
    assert!(result2.is_some());
    assert_eq!(result2.unwrap().target_hostname, "api.example.cn");
}

#[tokio::test]
async fn test_rewrite_sni_is_deterministic_without_unbounded_cache() {
    let config = create_test_config();
    let rewriter = BaseSniRewriter::new(config);

    let result1 = rewriter.rewrite("www.example.org").await;
    let result2 = rewriter.rewrite("www.example.org").await;
    assert_eq!(
        result1.map(|result| result.target_hostname),
        result2.map(|result| result.target_hostname)
    );
}

#[tokio::test]
async fn test_rewrite_sni_no_match() {
    let config = create_test_config();
    let rewriter = BaseSniRewriter::new(config);

    let result = rewriter.rewrite("unknown.com").await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_rewrite_arc() {
    let config = create_test_config();
    let rewriter = Arc::new(BaseSniRewriter::new(config));

    let result = rewriter.rewrite("www.example.org").await;
    assert!(result.is_some());
    assert_eq!(result.unwrap().target_hostname, "www.example.cn");
}
