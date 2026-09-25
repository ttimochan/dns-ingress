use dns_ingress::config::RewriteConfig;
use dns_ingress::rewrite::create_rewriter;
use dns_ingress::sni::SniRewriter;
use std::sync::Arc;

#[test]
fn test_create_rewriter() {
    let config = RewriteConfig {
        base_domains: vec!["test.com".to_string()],
        target_suffix: ".test.cn".to_string(),
    };

    let rewriter = create_rewriter(config);
    assert!(Arc::strong_count(&rewriter) >= 1);
}

#[tokio::test]
async fn test_create_rewriter_functionality() {
    let config = RewriteConfig {
        base_domains: vec!["test.com".to_string()],
        target_suffix: ".test.cn".to_string(),
    };

    let rewriter = create_rewriter(config);
    let result = rewriter.rewrite("www.test.com").await;

    assert!(result.is_some());
    let result = result.unwrap();
    assert_eq!(result.original, "www.test.com");
    assert_eq!(result.prefix, "www");
    assert_eq!(result.target_hostname, "www.test.cn");
}
