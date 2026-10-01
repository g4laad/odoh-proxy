use std::sync::Arc;

use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    process::Command,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    },
};

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn separate_clients_share_upstream_tls_connection_without_leaking_headers() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("target.pem");
    std::fs::write(&ca, cert.cert.pem()).unwrap();
    let tls = TlsAcceptor::from(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.cert.der().to_vec())],
                PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
            )
            .unwrap(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let target = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = tls.accept(socket).await.unwrap();
        let mut data = Vec::new();
        for (index, expected) in [b"first".as_slice(), b"second".as_slice()]
            .into_iter()
            .enumerate()
        {
            let end = loop {
                if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
                let mut buffer = [0; 4096];
                let n = socket.read(&mut buffer).await.unwrap();
                assert!(n > 0, "upstream connection closed before second POST");
                data.extend_from_slice(&buffer[..n]);
            };
            let headers = String::from_utf8_lossy(&data[..end]).to_ascii_lowercase();
            assert!(headers.starts_with("post /dns-query http/1.1\r\n"));
            assert!(headers.contains("content-type: application/oblivious-dns-message"));
            assert!(headers.contains("accept: application/oblivious-dns-message"));
            for forbidden in [
                "cookie:",
                "authorization:",
                "forwarded:",
                "x-forwarded-for:",
                "x-selected:",
                "proxy-status:",
            ] {
                assert!(!headers.contains(forbidden), "{headers}");
            }
            let length: usize = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            while data.len() - end < length {
                let mut buffer = [0; 4096];
                let n = socket.read(&mut buffer).await.unwrap();
                assert!(n > 0);
                data.extend_from_slice(&buffer[..n]);
            }
            assert_eq!(&data[end..end + length], expected);
            data.drain(..end + length);
            let (status, reply) = if index == 0 {
                ("401 Unauthorized", b"target auth".as_slice())
            } else {
                ("200 OK", b"opaque reply".as_slice())
            };
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/oblivious-dns-message\r\nContent-Length: {}\r\n\r\n",
                reply.len()
            );
            socket.write_all(head.as_bytes()).await.unwrap();
            socket.write_all(reply).await.unwrap();
        }
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "more than one upstream TCP connection"
        );
    });
    let mut relay = Command::new(env!("CARGO_BIN_EXE_odoh-proxy"))
        .args([
            "--listen",
            "127.0.0.1:0",
            "--target-ca-cert",
            ca.to_str().unwrap(),
            "--allowed-target",
            &format!("localhost:{port}"),
        ])
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut output = BufReader::new(relay.stdout.take().unwrap());
    let mut line = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        output.read_line(&mut line),
    )
    .await
    .unwrap()
    .unwrap();
    let addr = line.strip_prefix("LISTENING ").unwrap().trim();
    let url =
        format!("http://{addr}/dns-query?targethost=localhost%3A{port}&targetpath=%2Fdns-query");
    for (body, status, expected) in [
        (b"first".as_slice(), 401, b"target auth".as_slice()),
        (b"second".as_slice(), 200, b"opaque reply".as_slice()),
    ] {
        // Each downstream client owns a fresh connection pool.
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client
                .post(&url)
                .header("Content-Type", "application/oblivious-dns-message")
                .header("Cookie", "private")
                .header("Authorization", "Bearer private")
                .header("Forwarded", "for=private")
                .header("X-Forwarded-For", "private")
                .header("X-Selected", "private")
                .header("Proxy-Status", "client-owned")
                .body(body.to_vec())
                .send(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(
            response.headers()["proxy-status"],
            format!("odoh-proxy; received-status={status}")
        );
        assert_eq!(response.bytes().await.unwrap().as_ref(), expected);
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), target)
        .await
        .unwrap()
        .unwrap();
    relay.start_kill().unwrap();
    relay.wait().await.unwrap();
}
