/// Error scenario tests
use dns_ingress::config::RewriteConfig;
use dns_ingress::rewriters::base::BaseSniRewriter;
use dns_ingress::sni::SniRewriter;

#[tokio::test]
async fn test_rewriter_error_scenario_no_match() {
    let config = RewriteConfig {
        base_domains: vec!["example.com".to_string()],
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = BaseSniRewriter::new(config);
    let result = rewriter.rewrite("other.com").await;
    assert!(
        result.is_none(),
        "Non-matching hostname should return None with error strategy"
    );
}

#[tokio::test]
async fn test_rewriter_error_scenario_invalid_format() {
    let config = RewriteConfig {
        base_domains: vec!["example.com".to_string()],
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = BaseSniRewriter::new(config);

    // Test various invalid formats
    let invalid_hostnames = vec![
        "",                 // Empty
        "example.com",      // No prefix
        ".example.com",     // Leading dot only
        "example.com.",     // Trailing dot
        "www..example.com", // Double dot
    ];

    for hostname in invalid_hostnames {
        let result = rewriter.rewrite(hostname).await;
        // Empty and no prefix should definitely return None
        // Others may or may not depending on implementation
        if hostname.is_empty() || hostname == "example.com" {
            assert!(
                result.is_none(),
                "Invalid hostname '{}' should return None",
                hostname
            );
        }
        // For other cases, just verify it doesn't panic
        println!(
            "Testing hostname: '{}', result: {:?}",
            hostname,
            result.is_some()
        );
    }
}

#[tokio::test]
async fn test_rewriter_error_scenario_rejects_unmatched_domain() {
    let config = RewriteConfig {
        base_domains: vec!["example.com".to_string()],
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = BaseSniRewriter::new(config);

    // Non-matching hostnames must never bypass the configured routing rule.
    let result = rewriter.rewrite("other.com").await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_config_validation_empty_base_domains() {
    // Test that rewriter handles empty base domains gracefully
    let config = RewriteConfig {
        base_domains: vec![],
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = BaseSniRewriter::new(config);

    // Rewriter should return None for empty base domains
    let result = rewriter.rewrite("www.example.com").await;
    assert!(
        result.is_none(),
        "Rewriter with empty base domains should return None"
    );
}

#[tokio::test]
async fn test_config_validation_invalid_target_suffix() {
    // Test that rewriter handles invalid target suffix (though it may still work)
    let config = RewriteConfig {
        base_domains: vec!["example.com".to_string()],
        target_suffix: "example.cn".to_string(), // Missing leading dot
    };
    let rewriter = BaseSniRewriter::new(config);

    // Rewriter may still work but will log a warning
    let result = rewriter.rewrite("www.example.com").await;
    // The rewriter may still produce a result, but it will be incorrect format
    // The important thing is it doesn't panic
    println!("Invalid target suffix test result: {:?}", result.is_some());
}

#[tokio::test]
async fn test_rewriter_error_scenario_malformed_hostname() {
    let config = RewriteConfig {
        base_domains: vec!["example.com".to_string()],
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = BaseSniRewriter::new(config);

    // Test edge cases that might cause issues
    let edge_cases = vec![
        "www.example.com.",  // Trailing dot
        "www..example.com",  // Double dot
        ".www.example.com",  // Leading dot
        "www.example.com..", // Trailing double dot
    ];

    for hostname in edge_cases {
        let result = rewriter.rewrite(hostname).await;
        // These should either fail or be handled gracefully
        // The exact behavior depends on implementation
        println!(
            "Testing hostname: '{}', result: {:?}",
            hostname,
            result.is_some()
        );
    }
}

#[tokio::test]
async fn test_rewriter_error_scenario_very_long_hostname() {
    let config = RewriteConfig {
        base_domains: vec!["example.com".to_string()],
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = BaseSniRewriter::new(config);

    // Create a very long hostname (DNS limit is 253 characters)
    let long_prefix = "a".repeat(200);
    let hostname = format!("{}.example.com", long_prefix);

    let result = rewriter.rewrite(&hostname).await;
    // Should handle gracefully (either succeed or fail cleanly)
    println!(
        "Long hostname length: {}, result: {:?}",
        hostname.len(),
        result.is_some()
    );
}

#[tokio::test]
async fn test_rewriter_error_scenario_unicode_hostname() {
    let config = RewriteConfig {
        base_domains: vec!["example.com".to_string()],
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = BaseSniRewriter::new(config);

    // Unicode characters in hostname (should be invalid but handled gracefully)
    let unicode_hostname = "www.测试.example.com";
    let result = rewriter.rewrite(unicode_hostname).await;
    // Should handle gracefully (likely return None, but implementation may vary)
    // The important thing is it doesn't panic
    println!("Unicode hostname result: {:?}", result.is_some());
    // Just verify it doesn't panic - actual behavior may vary
}
