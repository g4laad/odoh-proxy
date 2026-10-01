use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    process::{Child, Command},
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    },
};

async fn launch(binary: &str, args: &[String]) -> (Child, SocketAddr) {
    let mut child = Command::new(binary)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        output.read_line(&mut line),
    )
    .await
    .unwrap()
    .unwrap();
    eprint!("{line}");
    let addr = line
        .strip_prefix("LISTENING ")
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    (child, addr)
}

#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn odoh_binary_forwards_both_uri_templates_without_allowlist() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("target.pem");
    std::fs::write(&ca, cert.cert.pem()).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let tls = TlsAcceptor::from(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.cert.der().to_vec())],
                key.into(),
            )
            .unwrap(),
    ));
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let count_server = count.clone();
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = target.accept().await.unwrap();
            let tls = tls.clone();
            let count = count_server.clone();
            tokio::spawn(async move {
                let mut stream = tls.accept(stream).await.unwrap();
                let mut data = Vec::new();
                let header_end = loop {
                    let mut buf = [0; 4096];
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    data.extend_from_slice(&buf[..n]);
                    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };
                let headers = String::from_utf8(data[..header_end].to_vec())
                    .unwrap()
                    .to_ascii_lowercase();
                let length: usize = headers
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length: "))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                while data.len() - header_end < length {
                    let mut buf = [0; 4096];
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    data.extend_from_slice(&buf[..n]);
                }
                let body = &data[header_end..header_end + length];
                assert!(headers.starts_with("post /dns-query http/1.1\r\n"));
                assert!(headers.contains("content-type: application/oblivious-dns-message"));
                assert!(headers.contains("accept: application/oblivious-dns-message"));
                for forbidden in [
                    "cookie:",
                    "authorization:",
                    "forwarded:",
                    "x-forwarded-",
                    "via:",
                ] {
                    assert!(!headers.contains(forbidden), "{headers}");
                }
                count.fetch_add(1, Ordering::SeqCst);
                let large = (body[0] == 4).then(|| vec![42; 256 * 1024 + 1]);
                let (status, content_type, reply): (&str, &str, &[u8]) = match body[0] {
                    1 => (
                        "302 Found",
                        "application/oblivious-dns-message",
                        b"redirect",
                    ),
                    2 => ("500 Internal Server Error", "text/plain", b"failure"),
                    3 => ("200 OK", "text/plain", b"invalid"),
                    4 => (
                        "200 OK",
                        "application/oblivious-dns-message",
                        large.as_deref().unwrap(),
                    ),
                    _ => ("200 OK", "application/oblivious-dns-message", body),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nLocation: https://elsewhere.invalid/\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.write_all(reply).await.unwrap();
                stream.shutdown().await.unwrap();
            });
        }
    });
    let (mut relay, addr) = launch(
        env!("CARGO_BIN_EXE_odoh-proxy"),
        &[
            "--listen".into(),
            "0.0.0.0:0".into(),
            "--target-ca-cert".into(),
            ca.to_str().unwrap().into(),
        ],
    )
    .await;
    assert!(addr.ip().is_unspecified());
    let addr = SocketAddr::from(([127, 0, 0, 1], addr.port()));
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let request = |query: &str, body: Vec<u8>| {
        client
            .post(format!("http://{addr}/dns-query?{query}"))
            .header("Content-Type", "application/oblivious-dns-message")
            .header("Cookie", "secret")
            .header("Authorization", "secret")
            .header("Forwarded", "for=secret")
            .header("X-Forwarded-For", "secret")
            .header("Via", "secret")
            .body(body)
    };
    let valid = format!("targethost=localhost%3A{port}&targetpath=%2Fdns-query");
    let bytes = vec![0, 0, 255, 13, 0];
    let response = request(&valid, bytes.clone()).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["proxy-status"],
        "odoh-proxy; received-status=200"
    );
    assert_eq!(
        response.headers()["content-type"],
        "application/oblivious-dns-message"
    );
    assert_eq!(response.bytes().await.unwrap().as_ref(), bytes);
    for path_url in [
        format!("http://{addr}/localhost:{port}/dns-query"),
        format!("http://{addr}/localhost:{port}/%2Fdns-query"),
    ] {
        let response = client
            .post(path_url)
            .header("Content-Type", "application/oblivious-dns-message")
            .body(bytes.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.bytes().await.unwrap().as_ref(), bytes);
    }
    for query in [
        "targethost=a&targethost=b&targetpath=%2Fdns-query",
        "targethost=localhost&targetpath=%2Fdns-query%3Fq=x",
        "targethost=localhost&targetpath=%FF",
        "targethost=localhost&targetpath=%G1",
        "targethost=localhost",
        "targethost=localhost&targetpath=%2Fdns-query&extra=1",
    ] {
        let response = request(query, vec![0]).send().await.unwrap();
        assert_eq!(response.status(), 400);
        assert_eq!(
            response.headers()["proxy-status"],
            "odoh-proxy; error=http_request_error"
        );
    }
    for url in [
        format!("http://{addr}/localhost:{port}/dns-query?targethost=other"),
        format!("http://{addr}/bad%2Fhost/dns-query"),
    ] {
        let response = client
            .post(url)
            .header("Content-Type", "application/oblivious-dns-message")
            .body(vec![0])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
        assert_eq!(
            response.headers()["proxy-status"],
            "odoh-proxy; error=http_request_error"
        );
    }
    for (response, status) in [
        (
            client
                .get(format!("http://{addr}/dns-query?{valid}"))
                .send()
                .await
                .unwrap(),
            405,
        ),
        (
            client
                .post(format!("http://{addr}/other?{valid}"))
                .send()
                .await
                .unwrap(),
            404,
        ),
        (request(&valid, vec![]).send().await.unwrap(), 400),
        (
            request(&valid, vec![0; 256 * 1024 + 1])
                .send()
                .await
                .unwrap(),
            413,
        ),
    ] {
        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers()["proxy-status"],
            "odoh-proxy; error=http_request_error"
        );
    }
    assert_eq!(count.load(Ordering::SeqCst), 3);
    for (body, status, expected) in [
        (vec![1], 302, b"redirect".as_slice()),
        (vec![2], 500, b"failure"),
        (vec![3], 502, b""),
    ] {
        let response = request(&valid, body).send().await.unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.bytes().await.unwrap().as_ref(), expected);
    }
    let response = request(&valid, vec![4]).send().await.unwrap();
    assert_eq!(response.status(), 502);
    assert_eq!(
        response.headers()["proxy-status"],
        "odoh-proxy; error=http_response_body_too_large"
    );
    assert_eq!(count.load(Ordering::SeqCst), 7);
    relay.start_kill().unwrap();
    relay.wait().await.unwrap();
    let rebound = TcpListener::bind(addr).await.unwrap();
    drop(rebound);
    server.abort();
}

#[tokio::test]
async fn invalid_configuration_and_bind_failures_exit_nonzero() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    for args in [
        vec![],
        vec![
            "--listen".into(),
            "127.0.0.1:0".into(),
            "--target-ca-cert".into(),
            "/nonexistent/private-ca.pem".into(),
        ],
        vec!["--listen".into(), tcp.local_addr().unwrap().to_string()],
    ] {
        let status = Command::new(env!("CARGO_BIN_EXE_odoh-proxy"))
            .args(args)
            .output()
            .await
            .unwrap();
        assert!(!status.status.success(), "accepted invalid configuration");
        assert!(status.stdout.is_empty(), "claimed to be listening");
    }
}
