use dns_ingress::quic::{QuicApplication, create_quic_server_endpoint};

#[test]
fn test_quic_module_imports() {
    // Test that quic module exports are accessible
    // Verify the function exists (just check it compiles)
    let _ = create_quic_server_endpoint;
}

#[test]
fn test_quic_application_alpn_is_protocol_specific() {
    assert_eq!(QuicApplication::Doq.alpn(), b"doq");
    assert_eq!(QuicApplication::H3.alpn(), b"h3");
}
