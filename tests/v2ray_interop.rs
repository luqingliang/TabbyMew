mod common;

use anyhow::{Context, Result, bail};
use common::{
    ChildGuard, TARGETS, TargetKind, TempDir, TlsFiles, assert_tcp_target_round_trip,
    assert_udp_target_round_trip, find_tool, print_process_logs, tool_version, unused_tcp_port,
    wait_for_tcp, write_json,
};
use serde_json::{Value, json};
use std::{net::SocketAddr, path::Path, process::Command};

const TROJAN_PASSWORD: &str = "example-password";

#[derive(Clone)]
struct V2RayCase {
    name: &'static str,
    protocol: &'static str,
    method_security: &'static str,
    udp: bool,
    v2ray_inbound: Value,
    tabby_outbound: Value,
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires V2Ray and localhost TCP/UDP socket access"]
async fn v2ray_real_server_core_protocols() -> Result<()> {
    let v2ray = find_tool("v2ray", "V2Ray")?;
    let version = tool_version(&v2ray, "V2Ray", "V2Ray version unknown")?;
    let temp = TempDir::new("tabbymew-v2ray-interop")?;
    let tls = generate_tls_keypair(&v2ray, temp.path())?;

    let mut results = Vec::new();
    for case in v2ray_cases(&tls) {
        for target in TARGETS {
            run_case(&v2ray, temp.path(), &case, target).await?;
            results.push(format!(
                "{} {} target={} TCP=Pass UDP={}",
                case.protocol,
                case.method_security,
                target.label(),
                if case.udp { "Pass" } else { "Skipped" }
            ));
        }
    }

    println!("V2Ray implementation: {version}");
    for result in results {
        println!("{result}");
    }

    Ok(())
}

fn v2ray_cases(tls: &TlsFiles) -> Vec<V2RayCase> {
    let stream_settings = || {
        json!({
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {
                "serverName": "localhost",
                "certificates": [{
                    "certificateFile": tls.cert_path,
                    "keyFile": tls.key_path,
                }]
            }
        })
    };
    let tls_outbound = || {
        json!({
            "server_name": "localhost",
            "insecure": true,
        })
    };

    vec![V2RayCase {
        name: "trojan",
        protocol: "Trojan",
        method_security: "TLS password auth",
        udp: true,
        v2ray_inbound: json!({
            "listen": "127.0.0.1",
            "port": 0,
            "protocol": "trojan",
            "settings": {
                "clients": [{"password": TROJAN_PASSWORD}],
            },
            "streamSettings": stream_settings(),
        }),
        tabby_outbound: json!({
            "type": "trojan",
            "tag": "server-out",
            "server": "127.0.0.1",
            "server_port": 0,
            "password": TROJAN_PASSWORD,
            "tls": tls_outbound(),
        }),
    }]
}

async fn run_case(v2ray: &Path, temp: &Path, case: &V2RayCase, target: TargetKind) -> Result<()> {
    println!(
        "running {} {} {} interop",
        case.protocol,
        case.method_security,
        target.label()
    );
    let server_port = unused_tcp_port()?;
    let socks_port = unused_tcp_port()?;
    let mut v2ray_inbound = case.v2ray_inbound.clone();
    v2ray_inbound["port"] = json!(server_port);
    let mut tabby_outbound = case.tabby_outbound.clone();
    tabby_outbound["server_port"] = json!(server_port);

    let v2ray_config = temp.join(format!("v2ray-{}-{}.json", case.name, target.label()));
    write_json(
        &v2ray_config,
        &json!({
            "log": {"loglevel": "error"},
            "inbounds": [v2ray_inbound],
            "outbounds": [{
                "protocol": "freedom",
                "tag": "direct",
                "settings": {},
            }],
            "routing": {"rules": []},
        }),
    )?;
    check_v2ray_config(v2ray, &v2ray_config)?;

    let v2ray_log = temp.join(format!("v2ray-{}-{}.log", case.name, target.label()));
    let _v2ray = ChildGuard::spawn(
        Command::new(v2ray).arg("run").arg("-c").arg(&v2ray_config),
        &v2ray_log,
    )
    .with_context(|| format!("failed to start V2Ray for {}", case.name))?;
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
                "listen_port": socks_port,
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
        print_process_logs("V2Ray", &v2ray_log, &tabby_log);
        return Err(err).with_context(|| format!("{} TCP interop failed", case.protocol));
    }
    if !case.udp {
        return Ok(());
    }
    if let Err(err) = assert_udp_target_round_trip(case.name, socks_port, target).await {
        print_process_logs("V2Ray", &v2ray_log, &tabby_log);
        return Err(err).with_context(|| format!("{} UDP interop failed", case.protocol));
    }
    Ok(())
}

fn check_v2ray_config(v2ray: &Path, config: &Path) -> Result<()> {
    let output = Command::new(v2ray)
        .arg("test")
        .arg("-c")
        .arg(config)
        .output()
        .context("failed to execute V2Ray config test")?;
    if !output.status.success() {
        bail!(
            "V2Ray config test failed for {}\nstdout:\n{}\nstderr:\n{}",
            config.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn generate_tls_keypair(v2ray: &Path, temp: &Path) -> Result<TlsFiles> {
    let base = temp.join("localhost");
    let output = Command::new(v2ray)
        .arg("tls")
        .arg("cert")
        .arg("--domain=localhost")
        .arg(format!("--file={}", base.display()))
        .output()
        .context("failed to generate V2Ray TLS keypair")?;
    if !output.status.success() {
        bail!(
            "V2Ray TLS keypair generation failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let cert_path = temp.join("localhost_cert.pem");
    let key_path = temp.join("localhost_key.pem");
    if !cert_path.exists() || !key_path.exists() {
        bail!(
            "V2Ray TLS keypair generation did not create {} and {}",
            cert_path.display(),
            key_path.display()
        );
    }
    Ok(TlsFiles {
        cert_path,
        key_path,
    })
}
