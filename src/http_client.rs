use reqwest::blocking::Client;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct HttpError {
    pub status: &'static str,
    pub detail: String,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.status, self.detail)
    }
}

#[derive(Debug, Default)]
pub struct HttpResponse {
    pub status: u16,
    pub server: String,
    pub realm: String,
    pub auth_scheme: String,
    pub location: String,
    pub url: String,
    pub body: String,
    pub body_error: Option<HttpError>,
    pub latency_ms: u64,
}
impl HttpResponse {
    pub fn is_ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
    pub fn needs_auth(&self) -> bool {
        self.status == 401 || self.status == 403
    }
}

pub fn tcp_connect(ip: Ipv4Addr, port: u16, timeout_ms: u64) -> io::Result<TcpStream> {
    TcpStream::connect_timeout(
        &SocketAddr::new(IpAddr::V4(ip), port),
        Duration::from_millis(timeout_ms.max(1)),
    )
}

// One shared client reuses connections; request timeouts cover headers and body.
// Redirects are handled below so a target cannot redirect the scan to another host.
static HTTP: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(2)
        .build()
        .expect("HTTP client initialization failed")
});

fn scheme(port: u16) -> &'static str {
    if matches!(port, 443 | 8443 | 9443) {
        "https"
    } else {
        "http"
    }
}

fn request_error(error: reqwest::Error, https: bool) -> HttpError {
    use std::error::Error;
    let mut detail = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        detail.push_str(": ");
        detail.push_str(&cause.to_string());
        source = cause.source();
    }
    let lower = detail.to_ascii_lowercase();
    let status = if error.is_timeout() {
        "Timed out"
    } else if https
        && (lower.contains("certificate") || lower.contains("tls") || lower.contains("ssl"))
    {
        "TLS error"
    } else if error.is_connect() {
        "Can't connect"
    } else {
        "Can't load"
    };
    HttpError { status, detail }
}

fn request_url(
    url: &reqwest::Url,
    headers: &[(&str, &str)],
    user_agent: &str,
    timeout: Duration,
    soap: Option<&str>,
) -> Result<HttpResponse, HttpError> {
    let start = Instant::now();
    let mut request = if let Some(body) = soap {
        HTTP.post(url.clone())
            .header(
                "SOAPAction",
                "\"http://purenetworks.com/HNAP1/GetDeviceSettings\"",
            )
            .header("Content-Type", "text/xml; charset=utf-8")
            .body(body.to_owned())
    } else {
        HTTP.get(url.clone())
    };
    request = request.timeout(timeout).header("User-Agent", user_agent);
    for &(key, value) in headers {
        request = request.header(key, value);
    }
    let response = request
        .send()
        .map_err(|e| request_error(e, url.scheme() == "https"))?;
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    let challenge = header("www-authenticate");
    let auth_scheme = challenge.split_whitespace().next().unwrap_or("").to_owned();
    let mut result = HttpResponse {
        status: response.status().as_u16(),
        server: header("server"),
        realm: extract_param(&challenge, "realm").unwrap_or_default(),
        auth_scheme,
        location: header("location"),
        url: url.to_string(),
        ..Default::default()
    };
    let mut bytes = Vec::new();
    // Bound memory even for chunked/compressed responses. Keep metadata on body errors.
    if let Err(error) = response.take(512 * 1024).read_to_end(&mut bytes) {
        use std::error::Error;
        let mut detail = error.to_string();
        let mut timed_out = matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        );
        let mut source: Option<&(dyn Error + 'static)> = error.source();
        while let Some(cause) = source {
            if let Some(http_error) = cause.downcast_ref::<reqwest::Error>() {
                timed_out |= http_error.is_timeout();
            }
            detail.push_str(": ");
            detail.push_str(&cause.to_string());
            source = cause.source();
        }
        let lower = detail.to_ascii_lowercase();
        result.body_error = Some(HttpError {
            status: if timed_out || lower.contains("timed out") || lower.contains("timeout") {
                "Timed out"
            } else {
                "Can't load"
            },
            detail,
        });
    }
    result.body = String::from_utf8_lossy(&bytes).into_owned();
    result.latency_ms = start.elapsed().as_millis() as u64;
    Ok(result)
}

/// HTTP POST with an arbitrary content-type and body string.
/// Used by exploit probes that need form-encoded or SOAP POST requests.
pub fn http_post_form(
    ip: Ipv4Addr,
    port: u16,
    path: &str,
    content_type: &str,
    body: &str,
    user_agent: &str,
    timeout_ms: u64,
) -> Option<HttpResponse> {
    let url = reqwest::Url::parse(&format!("{}://{}:{}{}", scheme(port), ip, port, path)).ok()?;
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms.max(1));
    let response = HTTP
        .post(url.clone())
        .timeout(timeout)
        .header("User-Agent", user_agent)
        .header("Content-Type", content_type)
        .body(body.to_owned())
        .send()
        .ok()?;
    let status = response.status().as_u16();
    let server = response
        .headers()
        .get("server")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let mut bytes = Vec::new();
    let _ = response.take(128 * 1024).read_to_end(&mut bytes);
    Some(HttpResponse {
        status,
        server,
        location,
        url: url.to_string(),
        body: String::from_utf8_lossy(&bytes).into_owned(),
        latency_ms: start.elapsed().as_millis() as u64,
        ..Default::default()
    })
}

pub fn http_get(
    ip: Ipv4Addr,
    port: u16,
    path: &str,
    headers: &[(&str, &str)],
    user_agent: &str,
    timeout_ms: u64,
) -> Result<HttpResponse, HttpError> {
    let mut url = reqwest::Url::parse(&format!("{}://{}:{}{}", scheme(port), ip, port, path))
        .map_err(|e| HttpError {
            status: "Can't load",
            detail: e.to_string(),
        })?;
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms.max(1));
    let original_origin = url.origin();
    let mut server = String::new();
    let mut realm = String::new();
    for hop in 0..=5 {
        let remaining = timeout
            .checked_sub(start.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| HttpError {
                status: "Timed out",
                detail: "Request deadline exceeded".into(),
            })?;
        let filtered: Vec<_> = headers
            .iter()
            .copied()
            .filter(|(key, _)| {
                url.origin() == original_origin
                    || !["authorization", "cookie", "proxy-authorization"]
                        .iter()
                        .any(|name| key.eq_ignore_ascii_case(name))
            })
            .collect();
        let mut response = request_url(&url, &filtered, user_agent, remaining, None)?;
        if response.server.is_empty() {
            response.server = server.clone();
        }
        if response.realm.is_empty() {
            response.realm = realm.clone();
        }
        server = response.server.clone();
        realm = response.realm.clone();
        if matches!(response.status, 301 | 302 | 303 | 307 | 308) && !response.location.is_empty() {
            let next = url.join(&response.location).map_err(|e| HttpError {
                status: "Can't load",
                detail: format!("Invalid redirect: {e}"),
            })?;
            if next.host_str() != Some(ip.to_string().as_str())
                || !matches!(next.scheme(), "http" | "https")
            {
                return Ok(response);
            }
            if hop == 5 {
                return Err(HttpError {
                    status: "Can't load",
                    detail: "Too many redirects".into(),
                });
            }
            if url.scheme() == "https" && next.scheme() == "http" {
                return Ok(response);
            }
            url = next;
        } else {
            return Ok(response);
        }
    }
    unreachable!()
}

fn extract_param(text: &str, name: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let needle = format!("{name}=");
    let pos = lower.find(&needle)?;
    let rest = text.get(pos + needle.len()..)?.trim_start();
    if let Some(rest) = rest.strip_prefix('"') {
        Some(rest.split('"').next()?.to_owned())
    } else {
        Some(rest.split([',', ' ', '\r', '\n']).next()?.to_owned())
    }
}

pub fn basic_auth_header(user: &str, pass: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}").as_bytes())
    )
}

pub fn try_basic_auth(
    ip: Ipv4Addr,
    port: u16,
    path: &str,
    pairs: &[(String, String)],
    user_agent: &str,
    timeout_ms: u64,
    cancelled: &dyn Fn() -> bool,
) -> Option<(String, String)> {
    for (user, pass) in pairs {
        if cancelled() {
            break;
        }
        let auth = basic_auth_header(user, pass);
        if let Ok(response) = http_get(
            ip,
            port,
            path,
            &[("Authorization", &auth)],
            user_agent,
            timeout_ms,
        ) {
            if response.is_ok() && response.body_error.is_none() {
                return Some((user.clone(), pass.clone()));
            }
        }
    }
    None
}

// ─── Device detection ────────────────────────────────────────────────────────

/// Detect device type from HTTP response metadata.
/// Returns a descriptive string like "D-Link Router", "TP-Link AP", etc.
pub fn detect_device(server: &str, realm: &str, body: &str) -> String {
    // Check server header first
    let server_lc = server.to_ascii_lowercase();
    let realm_lc = realm.to_ascii_lowercase();
    let body_lc = body.to_ascii_lowercase();

    // ── Server header patterns ────────────────────────────────────────────────
    if server_lc.contains("goahead") {
        if realm_lc.contains("d-link") || body_lc.contains("d-link") {
            return "D-Link (GoAhead)".into();
        }
        if body_lc.contains("tp-link") {
            return "TP-Link (GoAhead)".into();
        }
        return "GoAhead Web Server".into();
    }
    if server_lc.contains("micro_httpd") || server_lc.contains("mini_httpd") {
        return format!("MiniHTTPd Server ({})", server.trim());
    }
    if server_lc.contains("lighttpd") {
        return "Lighttpd Web Server".into();
    }
    if server_lc.contains("boa") {
        if body_lc.contains("asus") {
            return "ASUS Router (Boa)".into();
        }
        if body_lc.contains("d-link") {
            return "D-Link (Boa)".into();
        }
        return "Boa Web Server".into();
    }
    if server_lc.contains("uhttpd") {
        return "OpenWrt / LuCI (uHTTPd)".into();
    }
    if server_lc.contains("nginx") {
        return format!("Nginx ({})", server.trim());
    }
    if server_lc.contains("apache") {
        return format!("Apache ({})", server.trim());
    }
    if server_lc.contains("hikvision") || server_lc.contains("dvr") {
        return "Hikvision / DVR Camera".into();
    }
    if server_lc.contains("router") || server_lc.contains("broadband") {
        return format!("Generic Router ({})", server.trim());
    }

    // ── Realm patterns ────────────────────────────────────────────────────────
    if realm_lc.contains("d-link") {
        return "D-Link Router".into();
    }
    if realm_lc.contains("tp-link") || realm_lc.contains("tp_link") {
        return "TP-Link Device".into();
    }
    if realm_lc.contains("asus") {
        return "ASUS Router".into();
    }
    if realm_lc.contains("netgear") {
        return "NETGEAR Router".into();
    }
    if realm_lc.contains("zyxel") {
        return "ZyXEL Device".into();
    }
    if realm_lc.contains("linksys") {
        return "Cisco Linksys".into();
    }
    if realm_lc.contains("huawei") {
        return "Huawei Router".into();
    }
    if realm_lc.contains("zte") {
        return "ZTE Router".into();
    }
    if realm_lc.contains("tenda") {
        return "Tenda Router".into();
    }
    if realm_lc.contains("mikrotik") {
        return "MikroTik RouterOS".into();
    }
    if realm_lc.contains("broadband router") {
        return "Broadband Router".into();
    }
    if realm_lc.contains("wireless") {
        return "Wireless Router".into();
    }
    if realm_lc.contains("camera") {
        return "IP Camera".into();
    }

    // ── Body patterns ─────────────────────────────────────────────────────────
    if body_lc.contains("d-link") && (body_lc.contains("router") || body_lc.contains("dir-")) {
        return "D-Link Router".into();
    }
    if body_lc.contains("tp-link") {
        return "TP-Link Device".into();
    }
    if body_lc.contains("netgear") {
        return "NETGEAR Device".into();
    }
    if body_lc.contains("asus") && body_lc.contains("router") {
        return "ASUS Router".into();
    }
    if body_lc.contains("mikrotik") {
        return "MikroTik RouterOS".into();
    }
    if body_lc.contains("openwrt") {
        return "OpenWrt Router".into();
    }
    if body_lc.contains("dd-wrt") {
        return "DD-WRT Router".into();
    }
    if body_lc.contains("tomato") {
        return "Tomato Firmware".into();
    }
    if body_lc.contains("cisco") {
        return "Cisco Device".into();
    }
    if body_lc.contains("camera") || body_lc.contains("ipcam") {
        return "IP Camera".into();
    }

    // ── HTML title fallback ───────────────────────────────────────────────────
    if let Some(title) = extract_html_title(body) {
        if !title.trim().is_empty() {
            return title.trim().to_string();
        }
    }

    if !server.is_empty() {
        return server.trim().to_string();
    }

    realm.trim().to_owned()
}

fn extract_html_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let tag = lower.find("<title")?;
    let after = body.as_bytes().get(tag + 6)?;
    if !after.is_ascii_whitespace() && *after != b'>' {
        return None;
    }
    let start = tag + lower[tag..].find('>')? + 1;
    let end = lower[start..].find("</title")? + start;
    let title = body[start..end]
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ");
    Some(title.split_whitespace().collect::<Vec<_>>().join(" "))
}

pub fn probe_hnap(ip: Ipv4Addr, port: u16, user_agent: &str, timeout_ms: u64) -> Option<String> {
    let soap = r#"<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetDeviceSettings xmlns="http://purenetworks.com/HNAP1/"/></soap:Body></soap:Envelope>"#;
    let url = reqwest::Url::parse(&format!("{}://{}:{}/HNAP1/", scheme(port), ip, port)).ok()?;
    let response = request_url(
        &url,
        &[],
        user_agent,
        Duration::from_millis(timeout_ms.max(1)),
        Some(soap),
    )
    .ok()?;
    if !response.is_ok() || !response.body.contains("GetDeviceSettingsResponse") {
        return None;
    }
    let mut parts = Vec::new();
    for tag in ["VendorName", "ModelName", "DeviceName"] {
        if let Some(start) = response.body.find(&format!("<{tag}>")) {
            let value = &response.body[start + tag.len() + 2..];
            if let Some(end) = value.find(&format!("</{tag}>")) {
                let value = value[..end].trim();
                if !value.is_empty() && !parts.contains(&value) {
                    parts.push(value);
                }
            }
        }
    }
    Some(if parts.is_empty() {
        "HNAP device".into()
    } else {
        parts.join(" ")
    })
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use crate::test_support::{serve, Reply};

    #[test]
    fn follows_local_redirects_and_keeps_initial_metadata() {
        let (port, server) = serve(vec![
            Reply::new(
                "302 Found",
                "Server: RedirectServer\r\nLocation: /login\r\n",
                "",
            ),
            Reply::new(
                "200 OK",
                "",
                "<TITLE data-view='login'>Office &amp; Router</TITLE>",
            ),
        ]);
        let response = http_get(Ipv4Addr::LOCALHOST, port, "/", &[], "Fixture", 1000).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.server, "RedirectServer");
        assert!(response.url.ends_with("/login"));
        assert_eq!(
            detect_device(&response.server, &response.realm, &response.body),
            "Office & Router"
        );
        let requests = server.join().unwrap();
        assert!(requests[1].starts_with("GET /login "));
    }

    #[test]
    fn decodes_chunked_html_before_identification() {
        let body = "<title>Chunked Control Panel</title>";
        let reply = Reply {
            headers: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                .into(),
            body: format!("{:x}\r\n{}\r\n0\r\n\r\n", body.len(), body).into_bytes(),
            header_delay: Duration::ZERO,
            body_delay: Duration::ZERO,
            gate: None,
        };
        let (port, server) = serve(vec![reply]);
        let response = http_get(Ipv4Addr::LOCALHOST, port, "/", &[], "Fixture", 1000).unwrap();
        assert_eq!(response.body, body);
        assert_eq!(
            detect_device("", "", &response.body),
            "Chunked Control Panel"
        );
        server.join().unwrap();
    }

    #[test]
    fn non_http_response_is_an_error_instead_of_http_zero() {
        let mut reply = Reply::new("200 OK", "", "");
        reply.headers = "This is not an HTTP response\r\n\r\n".into();
        let (port, server) = serve(vec![reply]);
        let error = http_get(Ipv4Addr::LOCALHOST, port, "/", &[], "Fixture", 1000).unwrap_err();
        assert_eq!(error.status, "Can't load");
        server.join().unwrap();
    }

    #[test]
    fn realm_fallback_is_not_empty_for_unknown_devices() {
        assert_eq!(detect_device("", "Office Gateway", ""), "Office Gateway");
    }
}
