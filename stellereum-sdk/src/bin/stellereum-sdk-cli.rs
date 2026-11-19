//! `stellereum-sdk-cli`: key management and the Falcon signing helper used by
//! the TypeScript package.
//!
//! Commands:
//!
//! ```text
//! stellereum-sdk-cli keygen  [--out key.json]
//! stellereum-sdk-cli address --key key.json
//! stellereum-sdk-cli sign    --key key.json [--request req.json]   # stdin if omitted
//! stellereum-sdk-cli serve   --key key.json [--listen 127.0.0.1:8787]
//! stellereum-sdk-cli version
//! ```
//!
//! `sign` reads `{"tx":{...}}` and writes `{"ok":true,...}` (see
//! `src/signer.rs`). Errors are written as `{"ok":false,"error":{...}}` and
//! the process exits 1.

use std::io::Read;
use std::net::TcpListener;
use std::path::PathBuf;

use stellereum_sdk::key::FalconKeypair;
use stellereum_sdk::signer::{sign_request, SignErrorResponse, SignRequest};
use stellereum_sdk::SignerServer;

fn main() {
    if let Err(e) = run() {
        eprintln!("stellereum-sdk-cli: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        usage();
        return Err("missing command".into());
    };
    let rest: Vec<String> = args.collect();
    match cmd.as_str() {
        "keygen" => cmd_keygen(&rest),
        "address" => cmd_address(&rest),
        "sign" => cmd_sign(&rest),
        "sign-digest" => cmd_sign_digest(&rest),
        "serve" => cmd_serve(&rest),
        "version" | "--version" | "-V" => {
            println!("stellereum-sdk-cli {}", stellereum_sdk::VERSION);
            Ok(())
        }
        "help" | "--help" | "-h" => {
            usage();
            Ok(())
        }
        other => {
            usage();
            Err(format!("unknown command {other:?}"))
        }
    }
}

fn usage() {
    eprintln!(
        "usage:\n  \
         stellereum-sdk-cli keygen [--out KEY.json]\n  \
         stellereum-sdk-cli address --key KEY.json\n  \
         stellereum-sdk-cli sign --key KEY.json [--request REQ.json]\n  \
         stellereum-sdk-cli sign-digest --key KEY.json [--digest 0x..]\n  \
         stellereum-sdk-cli serve --key KEY.json [--listen 127.0.0.1:8787]\n  \
         stellereum-sdk-cli version"
    );
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn cmd_keygen(args: &[String]) -> Result<(), String> {
    let out = flag(args, "--out").map(PathBuf::from);
    let key = FalconKeypair::generate().map_err(|e| e.to_string())?;
    match out {
        Some(path) => {
            key.save_key_file(&path).map_err(|e| e.to_string())?;
            println!("wrote {}", path.display());
        }
        None => {
            let json =
                serde_json::to_string_pretty(&key.to_key_file()).map_err(|e| e.to_string())?;
            println!("{json}");
        }
    }
    // The address is public; the secret is only in the file/stdout above.
    eprintln!("address: {}", key.address_stl57());
    Ok(())
}

fn load_key(path: &str) -> Result<FalconKeypair, String> {
    FalconKeypair::load_key_file(std::path::Path::new(path)).map_err(|e| e.to_string())
}

fn cmd_address(args: &[String]) -> Result<(), String> {
    let path = flag(args, "--key").ok_or("address: --key is required")?;
    let key = load_key(&path)?;
    let addr = key.address();
    println!("{}", stellereum_sdk::address::encode_stl57(&addr));
    println!("{}", stellereum_sdk::address::to_hex(&addr));
    println!("pubkey {}", key.public_key_hex());
    Ok(())
}

fn cmd_sign(args: &[String]) -> Result<(), String> {
    let path = flag(args, "--key").ok_or("sign: --key is required")?;
    let key = load_key(&path)?;
    let raw = match flag(args, "--request") {
        Some(p) => std::fs::read(&p).map_err(|e| format!("read {p}: {e}"))?,
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| format!("stdin: {e}"))?;
            buf
        }
    };
    let req: SignRequest =
        serde_json::from_slice(&raw).map_err(|e| format!("request JSON: {e}"))?;
    match sign_request(&key, &req) {
        Ok((_, resp)) => {
            println!(
                "{}",
                serde_json::to_string(&resp).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        Err(e) => {
            println!(
                "{}",
                serde_json::to_string(&SignErrorResponse::from_error(&e))
                    .map_err(|e| e.to_string())?
            );
            Err(e.to_string())
        }
    }
}

fn cmd_sign_digest(args: &[String]) -> Result<(), String> {
    let path = flag(args, "--key").ok_or("sign-digest: --key is required")?;
    let key = load_key(&path)?;
    let digest = match flag(args, "--digest") {
        Some(d) => d,
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("stdin: {e}"))?;
            let value: serde_json::Value =
                serde_json::from_str(&buf).map_err(|e| format!("request JSON: {e}"))?;
            value
                .get("digest")
                .and_then(|v| v.as_str())
                .ok_or("sign-digest: missing 'digest'")?
                .to_string()
        }
    };
    let clean = digest.trim();
    let clean = clean.strip_prefix("0x").unwrap_or(clean);
    let bytes = hex::decode(clean).map_err(|e| format!("digest: bad hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("digest must be 32 bytes, got {}", bytes.len()));
    }
    let signature = key.sign(&bytes).map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::json!({ "ok": true, "signature": hex::encode(signature) })
    );
    Ok(())
}

fn cmd_serve(args: &[String]) -> Result<(), String> {
    let path = flag(args, "--key").ok_or("serve: --key is required")?;
    let key = load_key(&path)?;
    let listen = flag(args, "--listen").unwrap_or_else(|| "127.0.0.1:8787".into());
    let listener = TcpListener::bind(&listen).map_err(|e| format!("bind {listen}: {e}"))?;
    let token = std::env::var("STELL_SDK_SIGNER_TOKEN").ok();
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let server = SignerServer::start(listener, key, token).map_err(|e| format!("serve: {e}"))?;
    eprintln!(
        "signer listening on http://{addr} (address {})",
        server.address()
    );
    eprintln!("POST /sign with {{\"tx\": {{...}}}}; GET /health for liveness");
    if std::env::var("STELL_SDK_SIGNER_TOKEN").is_ok() {
        eprintln!("bearer token required (STELL_SDK_SIGNER_TOKEN is set)");
    }
    loop {
        std::thread::park();
    }
}
