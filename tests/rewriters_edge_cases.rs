use dns_ingress::config::RewriteConfig;
use dns_ingress::rewriters::base::BaseSniRewriter;
use dns_ingress::sni::SniRewriter;

#[tokio::test]
async fn test_rewriter_empty_sni() {
    let config = RewriteConfig {
        base_domains: vec!["example.com".to_string()],
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = BaseSniRewriter::new(config);
    let result = rewriter.rewrite("").await;
    assert!(result.is_none(), "Empty SNI should return None");
}

#[tokio::test]
async fn test_rewriter_empty_base_domains() {
    let config = RewriteConfig {
        base_domains: vec![],
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = BaseSniRewriter::new(config);
    let result = rewriter.rewrite("www.example.com").await;
    assert!(result.is_none(), "Empty base domains should return None");
}

#[tokio::test]
async fn test_rewriter_invalid_target_suffix() {
    let config = RewriteConfig {
        base_domains: vec!["example.com".to_string()],
        target_suffix: "example.cn".to_string(), // Missing leading dot
    };
    let rewriter = BaseSniRewriter::new(config);
    let _result = rewriter.rewrite("www.example.com").await;
    // Should still work but log a warning
    // The validation happens in rewrite() but doesn't prevent execution
}

#[tokio::test]
async fn test_rewriter_no_prefix() {
    let config = RewriteConfig {
        base_domains: vec!["example.com".to_string()],
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = BaseSniRewriter::new(config);
    let result = rewriter.rewrite("example.com").await;
    assert!(
        result.is_none(),
        "Hostname without prefix should return None"
    );
}

#[tokio::test]
async fn test_rewriter_rejects_unmatched_domain() {
    let config = RewriteConfig {
        base_domains: vec!["example.com".to_string()],
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = BaseSniRewriter::new(config);
    let result = rewriter.rewrite("other.com").await;
    assert!(
        result.is_none(),
        "Unmatched domains must not bypass routing"
    );
}

#[tokio::test]
async fn test_rewriter_multiple_base_domains() {
    let config = RewriteConfig {
        base_domains: vec![
            "example.com".to_string(),
            "example.org".to_string(),
            "example.net".to_string(),
        ],
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = BaseSniRewriter::new(config);

    // Test first domain
    let result1 = rewriter.rewrite("www.example.com").await;
    assert!(result1.is_some());
    assert_eq!(result1.unwrap().target_hostname, "www.example.cn");

    // Test second domain
    let result2 = rewriter.rewrite("api.example.org").await;
    assert!(result2.is_some());
    assert_eq!(result2.unwrap().target_hostname, "api.example.cn");

    // Test third domain
    let result3 = rewriter.rewrite("test.example.net").await;
    assert!(result3.is_some());
    assert_eq!(result3.unwrap().target_hostname, "test.example.cn");
}

#[tokio::test]
async fn test_rewriter_long_prefix() {
    let config = RewriteConfig {
        base_domains: vec!["example.com".to_string()],
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = BaseSniRewriter::new(config);
    let result = rewriter.rewrite("very-long-prefix-name.example.com").await;
    assert!(result.is_some());
    let rewrite_result = result.unwrap();
    assert_eq!(
        rewrite_result.prefix, "very-long-prefix-name",
        "Should extract long prefix correctly"
    );
    assert_eq!(
        rewrite_result.target_hostname,
        "very-long-prefix-name.example.cn"
    );
}

#[tokio::test]
async fn test_rewriter_special_characters_in_prefix() {
    let config = RewriteConfig {
        base_domains: vec!["example.com".to_string()],
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = BaseSniRewriter::new(config);
    // Note: DNS hostnames typically don't allow special characters,
    // but we test that the rewriter handles them gracefully
    let result = rewriter.rewrite("test-123.example.com").await;
    assert!(result.is_some());
    let rewrite_result = result.unwrap();
    assert_eq!(rewrite_result.prefix, "test-123");
}

#[tokio::test]
async fn test_rewriter_case_sensitivity() {
    let config = RewriteConfig {
        base_domains: vec!["Example.COM".to_string()], // Uppercase
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = BaseSniRewriter::new(config);
    // DNS names are case-insensitive, including configured base domains.
    let result = rewriter.rewrite("WWW.EXAMPLE.COM").await;
    assert!(result.is_some(), "Case-insensitive matching should succeed");
}

#[tokio::test]
async fn test_rewriter_repeated_rewrite_behavior() {
    let config = RewriteConfig {
        base_domains: vec!["example.com".to_string()],
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = BaseSniRewriter::new(config);

    // First rewrite
    let result1 = rewriter.rewrite("www.example.com").await;
    assert!(result1.is_some());

    // The rewriter is intentionally stateless; repeated input must remain stable.
    let result2 = rewriter.rewrite("www.example.com").await;
    assert!(result2.is_some());
    assert_eq!(
        result2.unwrap().target_hostname,
        "www.example.cn",
        "Second rewrite should return same result"
    );
}
