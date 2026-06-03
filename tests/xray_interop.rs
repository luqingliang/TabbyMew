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
struct XrayCase {
    name: &'static str,
    protocol: &'static str,
    method_security: &'static str,
    udp: bool,
    xray_inbound: Value,
    tabby_outbound: Value,
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires Xray and localhost TCP/UDP socket access"]
async fn xray_real_server_core_protocols() -> Result<()> {
    let xray = find_tool("xray", "Xray")?;
    let version = tool_version(&xray, "Xray", "Xray version unknown")?;
    let temp = TempDir::new("tabbymew-xray-interop")?;
    let tls = generate_tls_keypair(&xray, temp.path())?;

    let mut results = Vec::new();
    for case in xray_cases(&tls) {
        for target in TARGETS {
            run_case(&xray, temp.path(), &case, target).await?;
            results.push(format!(
                "{} {} target={} TCP=Pass UDP={}",
                case.protocol,
                case.method_security,
                target.label(),
                if case.udp { "Pass" } else { "Skipped" }
            ));
        }
    }

    println!("Xray implementation: {version}");
    for result in results {
        println!("{result}");
    }

    Ok(())
}

fn xray_cases(tls: &TlsFiles) -> Vec<XrayCase> {
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

    vec![XrayCase {
        name: "trojan",
        protocol: "Trojan",
        method_security: "TLS password auth",
        udp: true,
        xray_inbound: json!({
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

async fn run_case(xray: &Path, temp: &Path, case: &XrayCase, target: TargetKind) -> Result<()> {
    println!(
        "running {} {} {} interop",
        case.protocol,
        case.method_security,
        target.label()
    );
    let server_port = unused_tcp_port()?;
    let socks_port = unused_tcp_port()?;
    let mut xray_inbound = case.xray_inbound.clone();
    xray_inbound["port"] = json!(server_port);
    let mut tabby_outbound = case.tabby_outbound.clone();
    tabby_outbound["server_port"] = json!(server_port);

    let xray_config = temp.join(format!("xray-{}-{}.json", case.name, target.label()));
    write_json(
        &xray_config,
        &json!({
            "log": {"loglevel": "error"},
            "inbounds": [xray_inbound],
            "outbounds": [{
                "protocol": "freedom",
                "tag": "direct",
                "settings": {},
            }],
            "routing": {"rules": []},
        }),
    )?;
    check_xray_config(xray, &xray_config)?;

    let xray_log = temp.join(format!("xray-{}-{}.log", case.name, target.label()));
    let _xray = ChildGuard::spawn(
        Command::new(xray).arg("run").arg("-c").arg(&xray_config),
        &xray_log,
    )
    .with_context(|| format!("failed to start Xray for {}", case.name))?;
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
        print_process_logs("Xray", &xray_log, &tabby_log);
        return Err(err).with_context(|| format!("{} TCP interop failed", case.protocol));
    }
    if !case.udp {
        return Ok(());
    }
    if let Err(err) = assert_udp_target_round_trip(case.name, socks_port, target).await {
        print_process_logs("Xray", &xray_log, &tabby_log);
        return Err(err).with_context(|| format!("{} UDP interop failed", case.protocol));
    }
    Ok(())
}

fn check_xray_config(xray: &Path, config: &Path) -> Result<()> {
    let output = Command::new(xray)
        .arg("run")
        .arg("-test")
        .arg("-c")
        .arg(config)
        .output()
        .context("failed to execute Xray config test")?;
    if !output.status.success() {
        bail!(
            "Xray config test failed for {}\nstdout:\n{}\nstderr:\n{}",
            config.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn generate_tls_keypair(xray: &Path, temp: &Path) -> Result<TlsFiles> {
    let base = temp.join("localhost");
    let output = Command::new(xray)
        .arg("tls")
        .arg("cert")
        .arg("--domain=localhost")
        .arg(format!("--file={}", base.display()))
        .output()
        .context("failed to generate Xray TLS keypair")?;
    if !output.status.success() {
        bail!(
            "Xray TLS keypair generation failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let cert_path = temp.join("localhost.crt");
    let key_path = temp.join("localhost.key");
    if !cert_path.exists() || !key_path.exists() {
        bail!(
            "Xray TLS keypair generation did not create {} and {}",
            cert_path.display(),
            key_path.display()
        );
    }
    Ok(TlsFiles {
        cert_path,
        key_path,
    })
}
