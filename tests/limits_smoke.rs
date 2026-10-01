use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::Command,
    sync::oneshot,
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
async fn global_rate_and_capacity_reject_without_contacting_target() {
    for (flag, denial, proxy_status) in [
        (
            "--max-requests-per-second",
            429,
            "odoh-proxy; error=http_request_denied",
        ),
        (
            "--max-in-flight",
            503,
            "odoh-proxy; error=proxy_internal_response",
        ),
    ] {
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
        let count = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let target_count = count.clone();
        let server = tokio::spawn(async move {
            let mut started_tx = Some(started_tx);
            let mut release_rx = Some(release_rx);
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let tls = tls.clone();
                let count = target_count.clone();
                let first_release = release_rx.take();
                let first_started = started_tx.take();
                tokio::spawn(async move {
                    let mut stream = tls.accept(stream).await.unwrap();
                    let mut data = Vec::new();
                    let end = loop {
                        let mut buffer = [0; 4096];
                        let n = stream.read(&mut buffer).await.unwrap();
                        assert!(n > 0);
                        data.extend_from_slice(&buffer[..n]);
                        if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                    };
                    let headers = String::from_utf8_lossy(&data[..end]).to_ascii_lowercase();
                    let length: usize = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    while data.len() - end < length {
                        let mut buffer = [0; 4096];
                        let n = stream.read(&mut buffer).await.unwrap();
                        assert!(n > 0);
                        data.extend_from_slice(&buffer[..n]);
                    }
                    count.fetch_add(1, Ordering::SeqCst);
                    if let Some(release) = first_release {
                        first_started
                            .expect("first request signal")
                            .send(())
                            .unwrap();
                        release.await.unwrap();
                    }
                    let reply = &data[end..end + length];
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/oblivious-dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        reply.len()
                    );
                    stream.write_all(head.as_bytes()).await.unwrap();
                    stream.write_all(reply).await.unwrap();
                });
            }
        });
        let mut relay = Command::new(env!("CARGO_BIN_EXE_odoh-proxy"))
            .args([
                "--listen",
                "127.0.0.1:0",
                "--target-ca-cert",
                ca.to_str().unwrap(),
                flag,
                "1",
            ])
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut output = tokio::io::BufReader::new(relay.stdout.take().unwrap());
        let mut line = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            output.read_line(&mut line),
        )
        .await
        .unwrap()
        .unwrap();
        let addr = line.strip_prefix("LISTENING ").unwrap().trim();
        let url = format!(
            "http://{addr}/dns-query?targethost=localhost%3A{port}&targetpath=%2Fdns-query"
        );
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let send = |body: Vec<u8>| {
            client
                .post(&url)
                .header("Content-Type", "application/oblivious-dns-message")
                .body(body)
                .send()
        };
        let first = send(vec![1]);
        tokio::pin!(first);
        tokio::select! {
            result = started_rx => { result.unwrap(); },
            response = &mut first => panic!("first response arrived early: {response:?}"),
        }
        let second = send(vec![2]).await.unwrap();
        assert_eq!(second.status().as_u16(), denial);
        assert_eq!(second.headers()["proxy-status"], proxy_status);
        assert_eq!(second.headers()["cache-control"], "no-store");
        assert!(second.bytes().await.unwrap().is_empty());
        assert_eq!(count.load(Ordering::SeqCst), 1);
        release_tx.send(()).unwrap();
        assert_eq!(first.await.unwrap().bytes().await.unwrap().as_ref(), &[1]);
        if flag == "--max-requests-per-second" {
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        }
        let third = send(vec![3]).await.unwrap();
        assert_eq!(third.status(), 200);
        assert_eq!(third.bytes().await.unwrap().as_ref(), &[3]);
        assert_eq!(count.load(Ordering::SeqCst), 2);
        relay.start_kill().unwrap();
        relay.wait().await.unwrap();
        server.abort();
    }
}
