//! Opt-in end-to-end check requiring outbound HTTPS to Cloudflare's ODoH target.

use odoh_rs::{
    ObliviousDoHConfigs, ObliviousDoHMessagePlaintext, compose, decrypt_response, encrypt_query,
    parse,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};

const TARGET: &str = "odoh.cloudflare-dns.com";
const MEDIA_TYPE: &str = "application/oblivious-dns-message";
// DNS query: ID 0x1234, recursion desired, one IN A question for example.com.
const DNS_QUERY: &[u8] =
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";

#[tokio::test]
#[ignore = "requires outbound HTTPS to Cloudflare's live ODoH target"]
async fn encrypted_dns_query_through_proxy_reaches_cloudflare_target() {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();
    let mut configs_bytes = client
        .get(format!("https://{TARGET}/.well-known/odohconfigs"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let configs: ObliviousDoHConfigs = parse(&mut configs_bytes).unwrap();
    let config = configs
        .into_iter()
        .next()
        .expect("target has no ODoH config")
        .into();
    let query = ObliviousDoHMessagePlaintext::new(DNS_QUERY, 0);
    let (encrypted, secret) = encrypt_query(&query, &config, &mut rand::rng()).unwrap();
    let request = compose(&encrypted).unwrap().freeze();

    let mut proxy = Command::new(env!("CARGO_BIN_EXE_odoh-proxy"))
        .args(["--listen", "127.0.0.1:0", "--allowed-target", TARGET])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(proxy.stdout.take().unwrap());
    let mut listening = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stdout.read_line(&mut listening),
    )
    .await
    .unwrap()
    .unwrap();
    let addr = listening
        .trim()
        .strip_prefix("LISTENING ")
        .expect("proxy did not announce its listener");

    let response = client
        .post(format!(
            "http://{addr}/dns-query?targethost={TARGET}&targetpath=%2Fdns-query"
        ))
        .header("Content-Type", MEDIA_TYPE)
        .body(request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.headers()["proxy-status"],
        "odoh-proxy; received-status=200"
    );
    assert_eq!(response.headers()["content-type"], MEDIA_TYPE);
    let mut ciphertext = response.bytes().await.unwrap();
    let encrypted_response = parse(&mut ciphertext).unwrap();
    let plaintext = decrypt_response(&query, &encrypted_response, secret).unwrap();
    let dns_response = plaintext.into_msg();
    assert!(
        dns_response.len() >= DNS_QUERY.len(),
        "truncated DNS response"
    );
    assert_eq!(
        &dns_response[..2],
        &DNS_QUERY[..2],
        "transaction ID changed"
    );
    assert_eq!(dns_response[2] & 0x80, 0x80, "not a DNS response");
    assert_eq!(dns_response[3] & 0x0f, 0, "DNS query failed");
    assert_eq!(&dns_response[4..6], &[0, 1], "unexpected question count");
    assert_ne!(&dns_response[6..8], &[0, 0], "no A answers");
    assert_eq!(&dns_response[12..DNS_QUERY.len()], &DNS_QUERY[12..]);

    proxy.start_kill().unwrap();
    proxy.wait().await.unwrap();
}
