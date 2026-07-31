#[test]
fn t_single_client_constructor() {
    let transport = include_str!("../src/transport.rs");
    let subscription = include_str!("../src/subscription.rs");
    let combined = format!("{transport}\n{subscription}");

    assert_eq!(
        combined.matches("Client::builder()").count(),
        1,
        "RPC and SSE must share exactly one reqwest construction seam"
    );
    assert!(transport.contains("pub(crate) fn build_http_client"));
    assert!(transport.contains(".redirect(Policy::none())"));
    assert!(!subscription.contains("Client::builder()"));
    assert!(subscription.contains("build_http_client(HttpClientConfig::streaming"));
}
