use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Mutex as AsyncMutex,
    time::timeout,
};
use tracing::{info, warn};
use url::Url;

use crate::{
    config::{Config, TlsClientConfig},
    inbound,
    net::tls,
    outbound, router, subscription,
};

pub const DEFAULT_USER_AGENT: &str = "TabbyMew/0.1";
pub const DEFAULT_UPDATE_INTERVAL_SECONDS: u64 = 24 * 60 * 60;
pub const MIN_UPDATE_INTERVAL_SECONDS: u64 = 60;
pub const DEFAULT_TIMEOUT_MS: u64 = 15_000;
pub const DEFAULT_RETRIES: u8 = 2;

const STORE_FILE: &str = "tabbymew-subscriptions.json";
const STORE_VERSION: u32 = 4;
const PROFILES_DIR: &str = "profiles";
const SUBSCRIPTION_PROFILES_DIR: &str = "subscriptions";
const MAX_SUBSCRIPTION_BYTES: usize = 8 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;

include!("subscription_remote/model.rs");

include!("subscription_remote/store.rs");

include!("subscription_remote/runtime.rs");

include!("subscription_remote/fetch.rs");

include!("subscription_remote/normalize.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn fetches_http_subscription_and_follows_redirect() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    stream.read_exact(&mut byte).await.unwrap();
                    request.push(byte[0]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8(request).unwrap();
                if request.starts_with("GET /source ") || request.starts_with("GET /source?") {
                    stream
                        .write_all(b"HTTP/1.1 302 Found\r\nLocation: /target\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .unwrap();
                } else {
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nETag: test-etag\r\nContent-Length: 45\r\nConnection: close\r\n\r\nss://YWVzLTEyOC1nY206ZXhhbXBsZS1wYXNzd29yZA==")
                        .await
                        .unwrap();
                }
            }
        });

        let result = fetch_text(
            &format!("http://{addr}/source?token=example-token"),
            &FetchOptions {
                timeout: Duration::from_secs(1),
                retries: 0,
                user_agent: DEFAULT_USER_AGENT.to_string(),
            },
        )
        .await?;

        assert!(result.final_url.ends_with("/target"));
        assert_eq!(result.etag.as_deref(), Some("test-etag"));
        assert_eq!(result.body, "ss://YWVzLTEyOC1nY206ZXhhbXBsZS1wYXNzd29yZA==");
        task.await?;
        Ok(())
    }

    #[test]
    fn decodes_chunked_response_body() -> Result<()> {
        let body = decode_chunked(b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n")?;
        assert_eq!(body, b"Wikipedia");
        Ok(())
    }

    #[test]
    fn redacts_sensitive_url_parts() {
        assert_eq!(
            redact_url("https://user:example-password@example.com/sub?token=example-token#frag"),
            "https://redacted:redacted@example.com/sub?redacted#redacted"
        );
    }

    #[test]
    fn formats_ipv6_host_header() -> Result<()> {
        let url = Url::parse("http://[::1]:18080/sub")?;
        assert_eq!(host_header(&url, "::1"), "[::1]:18080");
        Ok(())
    }

    #[test]
    fn store_round_trips() -> Result<()> {
        let dir = std::env::temp_dir().join(format!(
            "tabbymew-subscription-store-test-{}-{}",
            std::process::id(),
            unix_now()
        ));
        fs::create_dir_all(&dir)?;
        let path = store_path(&dir);
        let mut store = SubscriptionStore::default();
        store.subscriptions.insert(
            "main".to_string(),
            SubscriptionRecord {
                name: "main".to_string(),
                source: SubscriptionSource::Remote,
                url: "https://example.com/sub?token=example-token".to_string(),
                output: dir.join("config.json"),
                inbound_tag: "hybrid-in".to_string(),
                listen: "127.0.0.1".to_string(),
                listen_port: 7890,
                user_agent: DEFAULT_USER_AGENT.to_string(),
                auto_update: true,
                update_interval_seconds: DEFAULT_UPDATE_INTERVAL_SECONDS,
                timeout_ms: DEFAULT_TIMEOUT_MS,
                retries: DEFAULT_RETRIES,
                last_checked_unix: Some(1),
                last_updated_unix: Some(1),
                last_success_unix: Some(1),
                next_update_unix: Some(2),
                last_error: None,
                imported: Some(1),
                warnings: Vec::new(),
                last_etag: Some("etag".to_string()),
                last_modified: None,
                last_final_url: None,
            },
        );

        save_store(&path, &store)?;
        let loaded = load_store(&path)?;

        assert_eq!(loaded.subscriptions["main"].imported, Some(1));
        assert_eq!(
            loaded.subscriptions["main"].output,
            subscription_output_path(&dir, "main")?
        );
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn subscription_files_are_private() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "tabbymew-subscription-private-files-test-{}-{}",
            std::process::id(),
            unix_now()
        ));
        fs::create_dir_all(&dir)?;
        let path = store_path(&dir);
        save_store(&path, &SubscriptionStore::default())?;

        let config: Config = serde_json::from_str(&Config::default_local_json()?)?;
        let output = subscription_output_path(&dir, "main")?;
        write_imported_config(&output, &config)?;

        assert_eq!(fs::metadata(&dir)?.permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(output.parent().unwrap())?.permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(fs::metadata(&output)?.permissions().mode() & 0o777, 0o600);

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn old_store_records_gain_auto_update_defaults() -> Result<()> {
        let dir = std::env::temp_dir().join(format!(
            "tabbymew-subscription-old-store-test-{}-{}",
            std::process::id(),
            unix_now()
        ));
        let json = r#"{
          "version": 1,
          "subscriptions": {
            "main": {
              "name": "main",
              "url": "https://example.com/sub?token=example-token",
              "output": "/tmp/config.json",
              "inbound_tag": "hybrid-in",
              "listen": "127.0.0.1",
              "listen_port": 7890,
              "user_agent": "TabbyMew/0.1"
            }
          }
        }"#;
        let mut store: SubscriptionStore = serde_json::from_str(json)?;
        normalize_store(&mut store, &store_path(&dir))?;
        let record = &store.subscriptions["main"];
        assert_eq!(record.source, SubscriptionSource::Remote);
        assert!(record.auto_update);
        assert_eq!(record.output, subscription_output_path(&dir, "main")?);
        assert_eq!(
            record.update_interval_seconds,
            DEFAULT_UPDATE_INTERVAL_SECONDS
        );
        assert_eq!(record.timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(record.retries, DEFAULT_RETRIES);
        Ok(())
    }

    #[test]
    fn old_store_output_is_migrated_to_name_scoped_profile() -> Result<()> {
        let dir = std::env::temp_dir().join(format!(
            "tabbymew-subscription-output-migration-test-{}-{}",
            std::process::id(),
            unix_now()
        ));
        fs::create_dir_all(&dir)?;
        let old_output = dir.join("custom-output.json");
        fs::write(&old_output, "{\"old\":true}\n")?;
        let new_output = subscription_output_path(&dir, "main")?;
        let mut store = SubscriptionStore::default();
        store.subscriptions.insert(
            "main".to_string(),
            SubscriptionRecord {
                name: "main".to_string(),
                source: SubscriptionSource::Remote,
                url: "https://example.com/sub?token=example-token".to_string(),
                output: old_output.clone(),
                inbound_tag: "hybrid-in".to_string(),
                listen: "127.0.0.1".to_string(),
                listen_port: 7890,
                user_agent: DEFAULT_USER_AGENT.to_string(),
                auto_update: true,
                update_interval_seconds: DEFAULT_UPDATE_INTERVAL_SECONDS,
                timeout_ms: DEFAULT_TIMEOUT_MS,
                retries: DEFAULT_RETRIES,
                last_checked_unix: None,
                last_updated_unix: None,
                last_success_unix: Some(1),
                next_update_unix: Some(2),
                last_error: None,
                imported: Some(1),
                warnings: Vec::new(),
                last_etag: None,
                last_modified: None,
                last_final_url: None,
            },
        );
        save_store(store_path(&dir), &store)?;

        let loaded = load_store(store_path(&dir))?;

        assert_eq!(loaded.subscriptions["main"].output, new_output);
        assert_eq!(fs::read_to_string(new_output)?, "{\"old\":true}\n");
        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[test]
    fn subscription_output_paths_are_name_scoped() -> Result<()> {
        let dir = PathBuf::from("/tmp/tabbymew-state");
        assert_eq!(
            subscription_output_path(&dir, "main")?,
            dir.join("profiles").join("subscriptions").join("main.json")
        );
        assert!(subscription_output_path(&dir, "..").is_err());
        Ok(())
    }

    #[test]
    fn disabled_records_are_not_due_for_auto_update() {
        let mut record = SubscriptionRecord {
            name: "main".to_string(),
            source: SubscriptionSource::Remote,
            url: "https://example.com/sub".to_string(),
            output: PathBuf::from("/tmp/config.json"),
            inbound_tag: "hybrid-in".to_string(),
            listen: "127.0.0.1".to_string(),
            listen_port: 7890,
            user_agent: DEFAULT_USER_AGENT.to_string(),
            auto_update: false,
            update_interval_seconds: 60,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            retries: DEFAULT_RETRIES,
            last_checked_unix: None,
            last_updated_unix: None,
            last_success_unix: None,
            next_update_unix: Some(1),
            last_error: None,
            imported: None,
            warnings: Vec::new(),
            last_etag: None,
            last_modified: None,
            last_final_url: None,
        };
        assert!(!record.is_due_for_auto_update(100));
        schedule_next_update(&mut record, 100).unwrap();
        assert_eq!(record.next_update_unix, None);
    }

    #[tokio::test]
    async fn import_uploaded_file_writes_non_refreshable_subscription() -> Result<()> {
        let dir = std::env::temp_dir().join(format!(
            "tabbymew-subscription-upload-test-{}-{}",
            std::process::id(),
            unix_now()
        ));
        let runtime = SubscriptionRuntime::new(&dir);
        let yaml = r#"
proxies:
  - name: file-trojan
    type: trojan
    server: trojan.example.com
    port: 443
    password: example-password
    sni: trojan.example.com
rules:
  - MATCH,file-trojan
"#;
        let report = runtime
            .import_uploaded(
                SubscriptionRecord {
                    name: "file-main".to_string(),
                    source: SubscriptionSource::UploadedFile,
                    url: uploaded_file_url(Some("../Flower.yaml")),
                    output: PathBuf::from("/tmp/ignored.json"),
                    inbound_tag: "hybrid-in".to_string(),
                    listen: "127.0.0.1".to_string(),
                    listen_port: 7890,
                    user_agent: DEFAULT_USER_AGENT.to_string(),
                    auto_update: true,
                    update_interval_seconds: MIN_UPDATE_INTERVAL_SECONDS,
                    timeout_ms: DEFAULT_TIMEOUT_MS,
                    retries: DEFAULT_RETRIES,
                    last_checked_unix: None,
                    last_updated_unix: None,
                    last_success_unix: None,
                    next_update_unix: Some(1),
                    last_error: None,
                    imported: None,
                    warnings: Vec::new(),
                    last_etag: None,
                    last_modified: None,
                    last_final_url: None,
                },
                yaml,
            )
            .await?;

        assert_eq!(report.source, SubscriptionSource::UploadedFile);
        assert_eq!(report.imported, 1);
        assert_eq!(report.url, "uploaded-file:Flower.yaml");
        assert!(report.next_update_unix.is_none());
        assert!(Path::new(&report.output).exists());

        let snapshot = runtime.snapshot().await?;
        assert_eq!(
            snapshot.subscriptions[0].source,
            SubscriptionSource::UploadedFile
        );
        assert!(!snapshot.subscriptions[0].auto_update);
        assert!(snapshot.subscriptions[0].next_update_unix.is_none());
        assert!(
            runtime
                .refresh_all(SubscriptionRefreshOverrides::default())
                .await?
                .is_empty()
        );
        assert!(
            runtime
                .refresh_one("file-main", SubscriptionRefreshOverrides::default())
                .await
                .is_err()
        );

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[tokio::test]
    async fn import_uploaded_clash_file_writes_native_dns_schema() -> Result<()> {
        let dir = std::env::temp_dir().join(format!(
            "tabbymew-subscription-native-dns-output-test-{}-{}",
            std::process::id(),
            unix_now()
        ));
        let runtime = SubscriptionRuntime::new(&dir);
        let yaml = r#"
dns:
  enable: true
  nameserver:
    - 1.1.1.1
    - tls://223.5.5.5:853
proxies:
  - name: file-trojan
    type: trojan
    server: trojan.example.com
    port: 443
    password: example-password
    sni: trojan.example.com
rules:
  - MATCH,file-trojan
"#;
        let report = runtime
            .import_uploaded(
                SubscriptionRecord {
                    name: "file-main".to_string(),
                    source: SubscriptionSource::UploadedFile,
                    url: uploaded_file_url(Some("Flower.yaml")),
                    output: PathBuf::from("/tmp/ignored.json"),
                    inbound_tag: "hybrid-in".to_string(),
                    listen: "127.0.0.1".to_string(),
                    listen_port: 7890,
                    user_agent: DEFAULT_USER_AGENT.to_string(),
                    auto_update: false,
                    update_interval_seconds: MIN_UPDATE_INTERVAL_SECONDS,
                    timeout_ms: DEFAULT_TIMEOUT_MS,
                    retries: DEFAULT_RETRIES,
                    last_checked_unix: None,
                    last_updated_unix: None,
                    last_success_unix: None,
                    next_update_unix: None,
                    last_error: None,
                    imported: None,
                    warnings: Vec::new(),
                    last_etag: None,
                    last_modified: None,
                    last_final_url: None,
                },
                yaml,
            )
            .await?;

        let output = PathBuf::from(&report.output);
        let text = fs::read_to_string(&output)?;
        assert!(!text.contains("\"nameserver\""));
        assert!(!text.contains("\"nameservers\""));
        assert!(text.contains("\"servers\""));
        let config = Config::load(&output)?;
        let dns = config.dns.as_ref().expect("dns should be imported");
        assert_eq!(dns.servers, vec!["1.1.1.1".to_string()]);
        validate_generated_config(&config)?;

        fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[tokio::test]
    async fn refresh_due_updates_enabled_subscriptions() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let body = include_str!("../examples/subscription-links.txt");
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let dir = std::env::temp_dir().join(format!(
            "tabbymew-subscription-auto-test-{}-{}",
            std::process::id(),
            unix_now()
        ));
        fs::create_dir_all(&dir)?;
        let output = subscription_output_path(&dir, "main")?;
        let mut store = SubscriptionStore::default();
        store.subscriptions.insert(
            "main".to_string(),
            SubscriptionRecord {
                name: "main".to_string(),
                source: SubscriptionSource::Remote,
                url: format!("http://{addr}/subscription-links.txt?token=example-token"),
                output: output.clone(),
                inbound_tag: "hybrid-in".to_string(),
                listen: "127.0.0.1".to_string(),
                listen_port: 7890,
                user_agent: DEFAULT_USER_AGENT.to_string(),
                auto_update: true,
                update_interval_seconds: MIN_UPDATE_INTERVAL_SECONDS,
                timeout_ms: 1000,
                retries: 0,
                last_checked_unix: None,
                last_updated_unix: None,
                last_success_unix: None,
                next_update_unix: Some(0),
                last_error: None,
                imported: None,
                warnings: Vec::new(),
                last_etag: None,
                last_modified: None,
                last_final_url: None,
            },
        );
        save_store(store_path(&dir), &store)?;

        let runtime = SubscriptionRuntime::new(&dir);
        let outcomes = runtime.refresh_due().await?;
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].ok);
        assert!(output.exists());

        let loaded = load_store(store_path(&dir))?;
        let record = &loaded.subscriptions["main"];
        assert_eq!(record.imported, Some(3));
        assert!(record.next_update_unix.unwrap() > unix_now());

        task.await?;
        fs::remove_dir_all(dir)?;
        Ok(())
    }
}
