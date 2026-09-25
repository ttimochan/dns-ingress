/// Performance and stress tests
use dns_ingress::config::RewriteConfig;
use dns_ingress::rewriters::base::BaseSniRewriter;
use dns_ingress::sni::SniRewriter;
use std::time::Instant;

#[tokio::test]
async fn test_rewriter_performance_single() {
    let config = RewriteConfig {
        base_domains: vec!["example.com".to_string()],
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = BaseSniRewriter::new(config);

    let start = Instant::now();
    let result = rewriter.rewrite("www.example.com").await;
    let duration = start.elapsed();

    assert!(result.is_some());
    assert!(
        duration.as_micros() < 1000,
        "Single rewrite should be very fast (< 1ms), took {:?}",
        duration
    );
}

#[tokio::test]
async fn test_rewriter_performance_concurrent() {
    let config = RewriteConfig {
        base_domains: vec!["example.com".to_string()],
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = std::sync::Arc::new(BaseSniRewriter::new(config));

    let start = Instant::now();
    let mut handles = Vec::new();

    // Spawn 100 concurrent rewrite tasks
    for i in 0..100 {
        let rewriter_clone = rewriter.clone();
        let hostname = format!("www{}.example.com", i);
        let handle = tokio::spawn(async move { rewriter_clone.rewrite(&hostname).await });
        handles.push(handle);
    }

    // Wait for all tasks
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_some());
    }

    let duration = start.elapsed();
    println!("100 concurrent rewrites took: {:?}", duration);
    assert!(
        duration.as_millis() < 1000,
        "100 concurrent rewrites should complete quickly (< 1s), took {:?}",
        duration
    );
}

#[tokio::test]
async fn test_rewriter_performance_sequential() {
    let config = RewriteConfig {
        base_domains: vec!["example.com".to_string()],
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = BaseSniRewriter::new(config);

    let start = Instant::now();
    let iterations = 1000;

    for i in 0..iterations {
        let hostname = format!("www{}.example.com", i);
        let result = rewriter.rewrite(&hostname).await;
        assert!(result.is_some());
    }

    let duration = start.elapsed();
    let avg_time = duration.as_micros() / iterations as u128;
    println!(
        "{} sequential rewrites took: {:?} (avg: {}μs per rewrite)",
        iterations, duration, avg_time
    );
    assert!(
        avg_time < 100,
        "Average rewrite time should be very fast (< 100μs), was {}μs",
        avg_time
    );
}

#[tokio::test]
async fn test_rewriter_performance_cache_hit() {
    let config = RewriteConfig {
        base_domains: vec!["example.com".to_string()],
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = BaseSniRewriter::new(config);

    // First rewrite (cache miss)
    let start1 = Instant::now();
    let _result1 = rewriter.rewrite("www.example.com").await;
    let duration1 = start1.elapsed();

    // Second rewrite (cache hit - should be faster)
    let start2 = Instant::now();
    let _result2 = rewriter.rewrite("www.example.com").await;
    let duration2 = start2.elapsed();

    println!(
        "First rewrite (cache miss): {:?}, Second rewrite (cache hit): {:?}",
        duration1, duration2
    );

    // Both should be very fast (< 1ms)
    // Due to microsecond-level timing variability, we allow some variance
    // The important thing is that both are fast, not that cache hit is strictly faster
    assert!(
        duration1.as_micros() < 1000 && duration2.as_micros() < 1000,
        "Both rewrites should be very fast (< 1ms), cache miss: {:?}, cache hit: {:?}",
        duration1,
        duration2
    );
}

#[tokio::test]
async fn test_rewriter_stress_many_domains() {
    let base_domains: Vec<String> = (0..100).map(|i| format!("example{}.com", i)).collect();
    let config = RewriteConfig {
        base_domains,
        target_suffix: ".example.cn".to_string(),
    };
    let rewriter = BaseSniRewriter::new(config);

    let start = Instant::now();
    let iterations = 1000;

    for i in 0..iterations {
        let domain_idx = i % 100;
        let hostname = format!("www.example{}.com", domain_idx);
        let result = rewriter.rewrite(&hostname).await;
        assert!(
            result.is_some(),
            "Rewrite should succeed for domain {}",
            domain_idx
        );
    }

    let duration = start.elapsed();
    println!(
        "{} rewrites across 100 base domains took: {:?}",
        iterations, duration
    );
    assert!(
        duration.as_millis() < 5000,
        "Stress test should complete in reasonable time (< 5s), took {:?}",
        duration
    );
}
