use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub struct Reply {
    pub headers: String,
    pub body: Vec<u8>,
    pub header_delay: Duration,
    pub body_delay: Duration,
    pub gate: Option<std::sync::mpsc::Receiver<()>>,
}

impl Reply {
    pub fn new(status: &str, headers: &str, body: &str) -> Self {
        Self {
            headers: format!(
                "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n",
                body.len()
            ),
            body: body.as_bytes().to_vec(),
            header_delay: Duration::ZERO,
            body_delay: Duration::ZERO,
            gate: None,
        }
    }
}

/// Only loopback is used. Empty TCP preflight connections do not consume a reply.
pub fn serve(replies: Vec<Reply>) -> (u16, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let mut requests = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        for reply in replies {
            loop {
                assert!(
                    Instant::now() < deadline,
                    "fixture did not receive an HTTP request"
                );
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                };
                // Accepted sockets inherit nonblocking mode on Windows.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            request.extend_from_slice(&buf[..n]);
                            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                if request.is_empty() {
                    continue;
                }
                requests.push(String::from_utf8_lossy(&request).into_owned());
                if let Some(gate) = reply.gate {
                    gate.recv_timeout(Duration::from_secs(2)).unwrap();
                }
                std::thread::sleep(reply.header_delay);
                let _ = stream.write_all(reply.headers.as_bytes());
                std::thread::sleep(reply.body_delay);
                let _ = stream.write_all(&reply.body);
                break;
            }
        }
        requests
    });
    (port, handle)
}
