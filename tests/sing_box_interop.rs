mod common;

use anyhow::{Context, Result, bail};
use common::{
    ChildGuard, TARGETS, TargetKind, TempDir, TlsFiles, assert_tcp_target_round_trip,
    assert_udp_target_round_trip, find_tool, print_process_logs, tool_version, unused_tcp_port,
    wait_for_tcp, write_json,
};
use serde_json::{Value, json};
use std::{fs, net::SocketAddr, path::Path, process::Command};

const TROJAN_PASSWORD: &str = "example-password";
const ANYTLS_PASSWORD: &str = "example-password";
const SHADOWSOCKS_PASSWORD: &str = "example-password";
const SHADOWSOCKS_2022_PASSWORD: &str = "AAAAAAAAAAAAAAAAAAAAAA==";

#[derive(Clone)]
struct InteropCase {
    name: &'static str,
    protocol: &'static str,
    method_security: &'static str,
    udp: bool,
    sing_box_inbound: Value,
    tabby_outbound: Value,
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires sing-box and localhost TCP/UDP socket access"]
async fn sing_box_real_server_protocols() -> Result<()> {
    let sing_box = find_tool("sing-box", "sing-box")?;
    let version = tool_version(&sing_box, "sing-box", "sing-box version unknown")?;
    let temp = TempDir::new("tabbymew-sing-box-interop")?;
    let tls = generate_tls_keypair(&sing_box, temp.path())?;

    let mut results = Vec::new();
    for case in interop_cases(&tls) {
        for target in TARGETS {
            run_case(&sing_box, temp.path(), &case, target).await?;
            results.push(format!(
                "{} {} target={} TCP=Pass UDP={}",
                case.protocol,
                case.method_security,
                target.label(),
                if case.udp { "Pass" } else { "Skipped" }
            ));
        }
    }

    println!("sing-box implementation: {version}");
    for result in results {
        println!("{result}");
    }

    Ok(())
}

fn interop_cases(tls: &TlsFiles) -> Vec<InteropCase> {
    let tls_inbound = || {
        json!({
            "enabled": true,
            "server_name": "localhost",
            "certificate_path": tls.cert_path,
            "key_path": tls.key_path,
        })
    };
    let tls_outbound = || {
        json!({
            "server_name": "localhost",
            "insecure": true,
        })
    };

    vec![
        InteropCase {
            name: "trojan",
            protocol: "Trojan",
            method_security: "TLS password auth",
            udp: true,
            sing_box_inbound: json!({
                "type": "trojan",
                "tag": "server-in",
                "listen": "127.0.0.1",
                "listen_port": 0,
                "users": [{"password": TROJAN_PASSWORD}],
                "tls": tls_inbound(),
            }),
            tabby_outbound: json!({
                "type": "trojan",
                "tag": "server-out",
                "server": "127.0.0.1",
                "server_port": 0,
                "password": TROJAN_PASSWORD,
                "tls": tls_outbound(),
            }),
        },
        InteropCase {
            name: "shadowsocks",
            protocol: "Shadowsocks",
            method_security: "aes-128-gcm",
            udp: true,
            sing_box_inbound: json!({
                "type": "shadowsocks",
                "tag": "server-in",
                "listen": "127.0.0.1",
                "listen_port": 0,
                "method": "aes-128-gcm",
                "password": SHADOWSOCKS_PASSWORD,
            }),
            tabby_outbound: json!({
                "type": "shadowsocks",
                "tag": "server-out",
                "server": "127.0.0.1",
                "server_port": 0,
                "method": "aes-128-gcm",
                "password": SHADOWSOCKS_PASSWORD,
            }),
        },
        InteropCase {
            name: "shadowsocks-2022",
            protocol: "Shadowsocks 2022",
            method_security: "2022-blake3-aes-128-gcm",
            udp: true,
            sing_box_inbound: json!({
                "type": "shadowsocks",
                "tag": "server-in",
                "listen": "127.0.0.1",
                "listen_port": 0,
                "method": "2022-blake3-aes-128-gcm",
                "password": SHADOWSOCKS_2022_PASSWORD,
            }),
            tabby_outbound: json!({
                "type": "shadowsocks-2022",
                "tag": "server-out",
                "server": "127.0.0.1",
                "server_port": 0,
                "method": "2022-blake3-aes-128-gcm",
                "password": SHADOWSOCKS_2022_PASSWORD,
            }),
        },
        InteropCase {
            name: "anytls",
            protocol: "AnyTLS",
            method_security: "UoT v2",
            udp: true,
            sing_box_inbound: json!({
                "type": "anytls",
                "tag": "server-in",
                "listen": "127.0.0.1",
                "listen_port": 0,
                "users": [{"password": ANYTLS_PASSWORD}],
                "tls": tls_inbound(),
            }),
            tabby_outbound: json!({
                "type": "anytls",
                "tag": "server-out",
                "server": "127.0.0.1",
                "server_port": 0,
                "password": ANYTLS_PASSWORD,
                "tls": tls_outbound(),
            }),
        },
    ]
}

async fn run_case(
    sing_box: &Path,
    temp: &Path,
    case: &InteropCase,
    target: TargetKind,
) -> Result<()> {
    println!(
        "running {} {} {} interop",
        case.protocol,
        case.method_security,
        target.label()
    );
    let server_port = unused_tcp_port()?;
    let socks_port = unused_tcp_port()?;
    let mut sing_box_inbound = case.sing_box_inbound.clone();
    sing_box_inbound["listen_port"] = json!(server_port);
    let mut tabby_outbound = case.tabby_outbound.clone();
    tabby_outbound["server_port"] = json!(server_port);

    let sing_box_config = temp.join(format!("sing-box-{}-{}.json", case.name, target.label()));
    write_json(
        &sing_box_config,
        &json!({
            "log": {"level": "error", "timestamp": false},
            "inbounds": [sing_box_inbound],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
        }),
    )?;
    check_sing_box_config(sing_box, &sing_box_config)?;

    let sing_box_log = temp.join(format!("sing-box-{}-{}.log", case.name, target.label()));
    let _sing_box = ChildGuard::spawn(
        Command::new(sing_box)
            .arg("run")
            .arg("-c")
            .arg(&sing_box_config),
        &sing_box_log,
    )
    .with_context(|| format!("failed to start sing-box for {}", case.name))?;
    wait_for_tcp(SocketAddr::from(([127, 0, 0, 1], server_port))).await?;

    let tabby_config = temp.join(format!("tabbymew-{}-{}.json", case.name, target.label()));
    write_json(
        &tabby_config,
        &json!({
            "log": {"level": "error"},
            "inbounds": [{
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": socks_port
            }],
            "outbounds": [tabby_outbound],
            "route": {"final": "server-out", "rules": []},
        }),
    )?;

    let tabby_log = temp.join(format!("tabbymew-{}-{}.log", case.name, target.label()));
    let _tabby = ChildGuard::spawn(
        Command::new(env!("CARGO_BIN_EXE_TabbyMew"))
            .arg("--config")
            .arg(&tabby_config),
        &tabby_log,
    )
    .with_context(|| format!("failed to start TabbyMew for {}", case.name))?;
    wait_for_tcp(SocketAddr::from(([127, 0, 0, 1], socks_port))).await?;

    if let Err(err) = assert_tcp_target_round_trip(case.name, socks_port, target).await {
        print_process_logs("sing-box", &sing_box_log, &tabby_log);
        return Err(err).with_context(|| format!("{} TCP interop failed", case.protocol));
    }
    if !case.udp {
        return Ok(());
    }
    if let Err(err) = assert_udp_target_round_trip(case.name, socks_port, target).await {
        print_process_logs("sing-box", &sing_box_log, &tabby_log);
        return Err(err).with_context(|| format!("{} UDP interop failed", case.protocol));
    }
    Ok(())
}

fn check_sing_box_config(sing_box: &Path, config: &Path) -> Result<()> {
    let output = Command::new(sing_box)
        .arg("check")
        .arg("-c")
        .arg(config)
        .output()
        .context("failed to execute sing-box check")?;
    if !output.status.success() {
        bail!(
            "sing-box check failed for {}\nstdout:\n{}\nstderr:\n{}",
            config.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn generate_tls_keypair(sing_box: &Path, temp: &Path) -> Result<TlsFiles> {
    let output = Command::new(sing_box)
        .args(["generate", "tls-keypair", "localhost"])
        .output()
        .context("failed to generate sing-box TLS keypair")?;
    if !output.status.success() {
        bail!(
            "sing-box TLS keypair generation failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let pem = String::from_utf8(output.stdout)?;
    let key = extract_pem_block(&pem, "PRIVATE KEY")?;
    let cert = extract_pem_block(&pem, "CERTIFICATE")?;
    let key_path = temp.join("localhost.key.pem");
    let cert_path = temp.join("localhost.cert.pem");
    fs::write(&key_path, key)?;
    fs::write(&cert_path, cert)?;
    Ok(TlsFiles {
        cert_path,
        key_path,
    })
}

fn extract_pem_block(pem: &str, label: &str) -> Result<String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem
        .find(&begin)
        .with_context(|| format!("missing PEM block {label}"))?;
    let end_index = pem[start..]
        .find(&end)
        .map(|index| start + index + end.len())
        .with_context(|| format!("missing PEM block end {label}"))?;
    Ok(format!("{}\n", &pem[start..end_index]))
}
