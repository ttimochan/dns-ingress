use dns_ingress::config::RewriteConfig;
use dns_ingress::rewrite::create_rewriter;
use dns_ingress::sni::SniRewriter;

#[tokio::test]
async fn test_rewriter_integration() {
    let rewriter = create_rewriter(RewriteConfig {
        base_domains: vec!["test.com".to_string()],
        target_suffix: ".test.cn".to_string(),
    });

    // Test that the rewriter works correctly
    let result = rewriter.rewrite("www.test.com").await;
    assert!(result.is_some());
    let rewrite_result = result.unwrap();
    assert_eq!(rewrite_result.original, "www.test.com");
    assert_eq!(rewrite_result.prefix, "www");
    assert_eq!(rewrite_result.target_hostname, "www.test.cn");
}

#[tokio::test]
async fn test_rewriter_no_match() {
    let rewriter = create_rewriter(RewriteConfig {
        base_domains: vec!["test.com".to_string()],
        target_suffix: ".test.cn".to_string(),
    });

    // Test with non-matching domain
    let result = rewriter.rewrite("example.com").await;
    assert!(result.is_none());
}

#[test]
fn test_proxy_module_imports() {
    // Test that proxy module exports are accessible
    // Verify the module structure exists (just check it compiles)
    let _ = create_rewriter;
}
