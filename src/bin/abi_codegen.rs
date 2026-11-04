//! ABI code generator: reads a JSON ABI manifest and emits typed Rust and
//! TypeScript client stubs.
//!
//! The generated stubs are the client-side counterpart of the on-chain ABI:
//! method names, parameter types, return types and event decoders all come
//! from the manifest, so a client never has to hand-pack arguments
//! (`from * 100_000_000 + to * 100_000 + amount`) or guess a parameter order.
//!
//! USAGE:
//!   cargo run --bin abi_codegen -- <manifest.json> [--lang rust|ts|both] [--out-dir <dir>]
//!
//! The manifest is read from the given path, or from stdin when the path is
//! `-`. The output files are `<manifest-stem>_client.rs` and
//! `<manifest-stem>_client.ts`, written to `--out-dir` (default: the
//! manifest's directory).
//!
//! EXAMPLE:
//!   cargo run --bin abi_codegen -- contracts/token.json --lang both --out-dir target/abi
//!
//! The emitted Rust stub depends on the `stellereum` crate
//! (`stellereum::contract_abi`); the emitted TypeScript stub is dependency
//! free and implements the very same wire format ("STELL-ABI v1").

use std::io::Read;
use std::path::{Path, PathBuf};

use stellereum::contract_abi::{AbiEvent, AbiMethod, AbiParam, AbiType, ContractAbi};

/// Where the generated code is going.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lang {
    Rust,
    Ts,
    Both,
}

fn main() {
    let mut manifest_path: Option<String> = None;
    let mut lang = Lang::Both;
    let mut out_dir: Option<PathBuf> = None;

    let mut argv = std::env::args().skip(1);
    while let Some(a) = argv.next() {
        match a.as_str() {
            "--lang" => {
                let v = argv.next().unwrap_or_else(|| {
                    eprintln!("--lang requires a value (rust|ts|both)");
                    std::process::exit(2);
                });
                lang = match v.as_str() {
                    "rust" | "rs" => Lang::Rust,
                    "ts" | "typescript" | "js" => Lang::Ts,
                    "both" | "all" => Lang::Both,
                    other => {
                        eprintln!("unknown language: {other} (expected rust|ts|both)");
                        std::process::exit(2);
                    }
                };
            }
            "--out-dir" | "-o" => {
                let v = argv.next().unwrap_or_else(|| {
                    eprintln!("--out-dir requires a value");
                    std::process::exit(2);
                });
                out_dir = Some(PathBuf::from(v));
            }
            "--help" | "-h" => {
                println!(
                    "usage: abi_codegen <manifest.json|-> [--lang rust|ts|both] [--out-dir <dir>]"
                );
                return;
            }
            other if other.starts_with('-') && other != "-" => {
                eprintln!("unknown flag: {other}");
                std::process::exit(2);
            }
            other => {
                if manifest_path.is_some() {
                    eprintln!("only one manifest may be given");
                    std::process::exit(2);
                }
                manifest_path = Some(other.to_string());
            }
        }
    }

    let manifest_path = manifest_path.unwrap_or_else(|| {
        eprintln!("usage: abi_codegen <manifest.json|-> [--lang rust|ts|both] [--out-dir <dir>]");
        std::process::exit(2);
    });

    let source_name = if manifest_path == "-" {
        "manifest.json".to_string()
    } else {
        manifest_path.clone()
    };
    let text = if manifest_path == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .expect("read manifest from stdin");
        buf
    } else {
        std::fs::read_to_string(&manifest_path)
            .unwrap_or_else(|e| panic!("read manifest {manifest_path}: {e}"))
    };

    let abi = ContractAbi::from_json(&text).unwrap_or_else(|e| {
        eprintln!("invalid ABI manifest: {e}");
        std::process::exit(1);
    });

    let stem = Path::new(&source_name)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "contract".to_string());
    let out_dir = out_dir.unwrap_or_else(|| {
        Path::new(&source_name)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
    });
    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        eprintln!("cannot create {}: {e}", out_dir.display());
        std::process::exit(1);
    }

    if lang == Lang::Rust || lang == Lang::Both {
        let path = out_dir.join(format!("{stem}_client.rs"));
        let code = generate_rust(&abi, &source_name);
        write_file(&path, &code);
        println!("wrote {}", path.display());
    }
    if lang == Lang::Ts || lang == Lang::Both {
        let path = out_dir.join(format!("{stem}_client.ts"));
        let code = generate_ts(&abi, &source_name);
        write_file(&path, &code);
        println!("wrote {}", path.display());
    }
}

fn write_file(path: &Path, content: &str) {
    if let Err(e) = std::fs::write(path, content) {
        eprintln!("cannot write {}: {e}", path.display());
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Rust type of an ABI type.
fn rust_type(ty: AbiType) -> &'static str {
    match ty {
        AbiType::I64 => "i64",
        AbiType::U64 => "u64",
        AbiType::I32 => "i32",
        AbiType::Bool => "bool",
        AbiType::Bytes => "Vec<u8>",
        AbiType::Address => "[u8; 32]",
        AbiType::String => "String",
    }
}

/// TypeScript type of an ABI type.
fn ts_type(ty: AbiType) -> &'static str {
    match ty {
        AbiType::I64 => "bigint",
        AbiType::U64 => "bigint",
        AbiType::I32 => "number",
        AbiType::Bool => "boolean",
        AbiType::Bytes => "Uint8Array",
        AbiType::Address => "Uint8Array",
        AbiType::String => "string",
    }
}

/// `AbiValue` constructor for a Rust type.
fn rust_value(ty: AbiType, expr: &str) -> String {
    match ty {
        AbiType::I64 => format!("AbiValue::I64({expr})"),
        AbiType::U64 => format!("AbiValue::U64({expr})"),
        AbiType::I32 => format!("AbiValue::I32({expr})"),
        AbiType::Bool => format!("AbiValue::Bool({expr})"),
        AbiType::Bytes => format!("AbiValue::Bytes({expr})"),
        AbiType::Address => format!("AbiValue::Address({expr})"),
        AbiType::String => format!("AbiValue::String({expr})"),
    }
}

/// Name of the generated accessor that unwraps an `AbiValue` into the Rust type.
fn expect_fn(ty: AbiType) -> &'static str {
    match ty {
        AbiType::I64 => "expect_i64",
        AbiType::U64 => "expect_u64",
        AbiType::I32 => "expect_i32",
        AbiType::Bool => "expect_bool",
        AbiType::Bytes => "expect_bytes",
        AbiType::Address => "expect_address",
        AbiType::String => "expect_string",
    }
}

/// A safe Rust identifier derived from a contract method / event name.
fn rust_ident(name: &str) -> String {
    let mut out = String::new();
    for (i, ch) in name.chars().enumerate() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            if i == 0 && ch.is_ascii_digit() {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push('_');
    }
    out
}

/// A safe TypeScript identifier derived from a contract method / event name.
fn ts_ident(name: &str) -> String {
    let mut out = String::new();
    for (i, ch) in name.chars().enumerate() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' {
            if i == 0 && ch.is_ascii_digit() {
                out.push('_');
            }
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push('_');
    }
    out
}

/// Human readable signature, e.g. `transfer(to: address, amount: u64) -> bool`.
fn signature(m: &AbiMethod) -> String {
    let params = m
        .params
        .iter()
        .map(|p| format!("{}: {}", p.name, p.ty))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{}({}) -> {}", m.name, params, m.returns)
}

// ---------------------------------------------------------------------------
// Rust generator
// ---------------------------------------------------------------------------

fn generate_rust(abi: &ContractAbi, source: &str) -> String {
    let mut out = String::new();
    out.push_str("// @generated by `cargo run --bin abi_codegen` from ");
    out.push_str(source);
    out.push_str(" — do not edit by hand.\n");
    out.push_str("//\n");
    out.push_str("// Typed client stub: every method, parameter type, return type and event\n");
    out.push_str("// comes from the contract's ABI manifest.\n");
    out.push_str("#![allow(dead_code, unused_variables, unused_imports, clippy::all)]\n\n");
    out.push_str("use std::sync::OnceLock;\n");
    out.push_str("use stellereum::contract_abi::{AbiError, AbiValue, ContractAbi};\n\n");

    // The manifest itself, embedded so the stub is self-contained.
    out.push_str("/// The ABI manifest this client was generated from.\n");
    out.push_str("pub const ABI_JSON: &str = r#\"");
    out.push_str(&abi.to_json());
    out.push_str("\"#;\n\n");

    out.push_str("/// The parsed ABI manifest (cached).\n");
    out.push_str("pub fn abi() -> &'static ContractAbi {\n");
    out.push_str("    static ABI: OnceLock<ContractAbi> = OnceLock::new();\n");
    out.push_str("    ABI.get_or_init(|| ContractAbi::from_json(ABI_JSON).expect(\"embedded ABI manifest is valid\"))\n");
    out.push_str("}\n\n");

    out.push_str("/// Typed client for the contract described by [`ABI_JSON`].\n");
    out.push_str("pub struct ContractClient {\n    abi: ContractAbi,\n}\n\n");
    out.push_str("impl Default for ContractClient {\n    fn default() -> Self {\n        Self::new()\n    }\n}\n\n");
    out.push_str("impl ContractClient {\n");
    out.push_str("    /// Build a client from the embedded manifest.\n");
    out.push_str("    pub fn new() -> Self {\n        Self { abi: abi().clone() }\n    }\n\n");
    out.push_str("    /// Build a client from an explicit manifest.\n");
    out.push_str(
        "    pub fn with_abi(abi: ContractAbi) -> Self {\n        Self { abi }\n    }\n\n",
    );
    out.push_str("    /// The manifest this client speaks.\n");
    out.push_str("    pub fn abi(&self) -> &ContractAbi {\n        &self.abi\n    }\n\n");
    out.push_str("    /// Encode a full call payload (method selector + arguments).\n");
    out.push_str("    pub fn encode_call(&self, method: &str, args: &[AbiValue]) -> Result<Vec<u8>, AbiError> {\n");
    out.push_str("        self.abi.encode_call(method, args)\n    }\n\n");
    out.push_str("    /// Encode the arguments of a call.\n");
    out.push_str("    pub fn encode_args(&self, method: &str, args: &[AbiValue]) -> Result<Vec<u8>, AbiError> {\n");
    out.push_str("        self.abi.encode_args(method, args)\n    }\n\n");
    out.push_str("    /// Decode the arguments of a call.\n");
    out.push_str("    pub fn decode_args(&self, method: &str, bytes: &[u8]) -> Result<Vec<AbiValue>, AbiError> {\n");
    out.push_str("        self.abi.decode_args(method, bytes)\n    }\n\n");
    out.push_str("    /// Decode the return value of a call.\n");
    out.push_str("    pub fn decode_return(&self, method: &str, bytes: &[u8]) -> Result<AbiValue, AbiError> {\n");
    out.push_str("        self.abi.decode_return(method, bytes)\n    }\n\n");

    for m in &abi.methods {
        let ident = rust_ident(&m.name);
        let params: Vec<String> = m
            .params
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let arg = rust_ident(&p.name);
                let name = if arg.is_empty() || arg == "_" {
                    format!("arg{i}")
                } else {
                    arg
                };
                format!("{name}: {}", rust_type(p.ty))
            })
            .collect();
        let args: Vec<String> = m
            .params
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let arg = rust_ident(&p.name);
                let name = if arg.is_empty() || arg == "_" {
                    format!("arg{i}")
                } else {
                    arg
                };
                rust_value(p.ty, &name)
            })
            .collect();
        out.push_str(&format!(
            "    /// `{}`\n    pub fn {ident}(&self{}) -> Result<Vec<u8>, AbiError> {{\n",
            signature(m),
            if params.is_empty() {
                String::new()
            } else {
                format!(", {}", params.join(", "))
            }
        ));
        out.push_str(&format!(
            "        self.encode_call(\"{}\", &[{}])\n    }}\n\n",
            m.name,
            args.join(", ")
        ));
    }
    out.push_str("}\n\n");

    // Event decoders.
    for e in &abi.events {
        let ident = rust_ident(&e.name);
        out.push_str(&format!(
            "/// Decode a `{}` event: topics ({}), data ({}).\n",
            e.name,
            e.topics
                .iter()
                .map(|p| format!("{}: {}", p.name, p.ty))
                .collect::<Vec<_>>()
                .join(", "),
            e.data
                .iter()
                .map(|p| format!("{}: {}", p.name, p.ty))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        out.push_str(&format!(
            "pub fn decode_{ident}_event(bytes: &[u8]) -> Result<(Vec<AbiValue>, Vec<AbiValue>), AbiError> {{\n"
        ));
        out.push_str(&format!(
            "    abi().decode_event(\"{}\", bytes)\n}}\n\n",
            e.name
        ));
    }

    // Typed event structs: one per event, with named fields.
    for e in &abi.events {
        let struct_name = format!("{}Event", to_pascal(&e.name));
        out.push_str(&format!("/// Decoded `{}` event.\n", e.name));
        out.push_str(&format!("pub struct {struct_name} {{\n"));
        for p in &e.topics {
            out.push_str(&format!(
                "    /// Topic field `{}`.\n    pub {field}: {ty},\n",
                p.name,
                field = rust_ident(&p.name),
                ty = rust_type(p.ty)
            ));
        }
        for p in &e.data {
            out.push_str(&format!(
                "    /// Data field `{}`.\n    pub {field}: {ty},\n",
                p.name,
                field = rust_ident(&p.name),
                ty = rust_type(p.ty)
            ));
        }
        out.push_str("}\n\n");
        out.push_str(&format!("impl {struct_name} {{\n"));
        out.push_str("    /// Decode the event from its canonical payload.\n    pub fn decode(bytes: &[u8]) -> Result<Self, AbiError> {\n");
        out.push_str(&format!(
            "        let (topics, data) = abi().decode_event(\"{}\", bytes)?;\n",
            e.name
        ));
        out.push_str(
            "        let mut topic_index = 0usize;\n        let mut data_index = 0usize;\n",
        );
        for (i, p) in e.topics.iter().enumerate() {
            let field = rust_ident(&p.name);
            out.push_str(&format!(
                "        let {field} = {}(topics.get({i}))?;\n",
                expect_fn(p.ty)
            ));
        }
        for (i, p) in e.data.iter().enumerate() {
            let field = rust_ident(&p.name);
            out.push_str(&format!(
                "        let {field} = {}(data.get({i}))?;\n",
                expect_fn(p.ty)
            ));
        }
        out.push_str("        let _ = (&mut topic_index, &mut data_index);\n");
        out.push_str(&format!("        Ok({struct_name} {{\n"));
        for p in e.topics.iter().chain(e.data.iter()) {
            out.push_str(&format!("            {},\n", rust_ident(&p.name)));
        }
        out.push_str("        })\n    }\n}\n\n");
    }

    // Small typed accessors used by the event structs.
    out.push_str("fn expect_i64(v: Option<&AbiValue>) -> Result<i64, AbiError> {\n    v.and_then(|v| v.as_i64())\n        .ok_or_else(|| AbiError::Json(\"expected an i64 event field\".to_string()))\n}\n\n");
    out.push_str("fn expect_u64(v: Option<&AbiValue>) -> Result<u64, AbiError> {\n    v.and_then(|v| v.as_u64())\n        .ok_or_else(|| AbiError::Json(\"expected a u64 event field\".to_string()))\n}\n\n");
    out.push_str("fn expect_i32(v: Option<&AbiValue>) -> Result<i32, AbiError> {\n    match v {\n        Some(AbiValue::I32(x)) => Ok(*x),\n        Some(AbiValue::I64(x)) => Ok(*x as i32),\n        _ => Err(AbiError::Json(\"expected an i32 event field\".to_string())),\n    }\n}\n\n");
    out.push_str("fn expect_bool(v: Option<&AbiValue>) -> Result<bool, AbiError> {\n    v.and_then(|v| v.as_bool())\n        .ok_or_else(|| AbiError::Json(\"expected a bool event field\".to_string()))\n}\n\n");
    out.push_str("fn expect_bytes(v: Option<&AbiValue>) -> Result<Vec<u8>, AbiError> {\n    v.and_then(|v| v.as_bytes())\n        .map(|b| b.to_vec())\n        .ok_or_else(|| AbiError::Json(\"expected a bytes event field\".to_string()))\n}\n\n");
    out.push_str("fn expect_address(v: Option<&AbiValue>) -> Result<[u8; 32], AbiError> {\n    v.and_then(|v| v.as_address())\n        .ok_or_else(|| AbiError::Json(\"expected an address event field\".to_string()))\n}\n\n");
    out.push_str("fn expect_string(v: Option<&AbiValue>) -> Result<String, AbiError> {\n    v.and_then(|v| v.as_str())\n        .map(|s| s.to_string())\n        .ok_or_else(|| AbiError::Json(\"expected a string event field\".to_string()))\n}\n\n");

    out
}

/// `transfer` -> `Transfer`.
fn to_pascal(name: &str) -> String {
    let mut out = String::new();
    let mut upper = true;
    for ch in name.chars() {
        if ch == '_' || ch == '-' || ch == ' ' {
            upper = true;
            continue;
        }
        if upper {
            out.extend(ch.to_uppercase());
            upper = false;
        } else {
            out.push(ch);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// TypeScript generator
// ---------------------------------------------------------------------------

fn generate_ts(abi: &ContractAbi, source: &str) -> String {
    let mut out = String::new();
    out.push_str("// @generated by `cargo run --bin abi_codegen` from ");
    out.push_str(source);
    out.push_str(" — do not edit by hand.\n");
    out.push_str("//\n");
    out.push_str("// Typed client stub for the contract ABI. Implements the same wire format\n");
    out.push_str("// as the node (\"STELL-ABI v1\"): u32-le argument count, then one\n");
    out.push_str("// type-tagged, length-prefixed value per parameter, in declaration order.\n\n");

    out.push_str("export type AbiValue = bigint | number | boolean | Uint8Array | string;\n\n");
    out.push_str("export const ABI_JSON = ");
    out.push_str(&json_string(&abi.to_json()));
    out.push_str(";\n\n");
    out.push_str("const MANIFEST = JSON.parse(ABI_JSON) as AbiManifest;\n\n");

    out.push_str(TS_RUNTIME);

    out.push_str("/** Typed client for the contract described by `ABI_JSON`. */\n");
    out.push_str("export class ContractClient {\n");
    out.push_str("  readonly abi: AbiManifest;\n\n");
    out.push_str("  constructor(abi: AbiManifest = JSON.parse(ABI_JSON) as AbiManifest) {\n");
    out.push_str("    this.abi = abi;\n  }\n\n");

    for m in &abi.methods {
        let ident = ts_ident(&m.name);
        let params: Vec<String> = m
            .params
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let name = ts_ident(&p.name);
                let name = if name.is_empty() {
                    format!("arg{i}")
                } else {
                    name
                };
                format!("{name}: {}", ts_type(p.ty))
            })
            .collect();
        out.push_str(&format!("  /** `{}` */\n", signature(m)));
        out.push_str(&format!(
            "  async {ident}({}): Promise<Uint8Array> {{\n",
            params.join(", ")
        ));
        out.push_str(&format!(
            "    return encodeCall(this.abi, \"{}\", [",
            m.name
        ));
        out.push_str(
            &m.params
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    let name = ts_ident(&p.name);
                    let name = if name.is_empty() {
                        format!("arg{i}")
                    } else {
                        name
                    };
                    name.to_string()
                })
                .collect::<Vec<_>>()
                .join(", "),
        );
        out.push_str("]);\n  }\n\n");
    }
    out.push_str("}\n\n");

    for e in &abi.events {
        let ident = ts_ident(&e.name);
        out.push_str(&format!(
            "/** Decode a `{}` event: topics ({}), data ({}). */\n",
            e.name,
            e.topics
                .iter()
                .map(|p| format!("{}: {}", p.name, p.ty))
                .collect::<Vec<_>>()
                .join(", "),
            e.data
                .iter()
                .map(|p| format!("{}: {}", p.name, p.ty))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        out.push_str(&format!(
            "export function decode{ident}Event(bytes: Uint8Array): {{ topics: AbiValue[]; data: AbiValue[] }} {{\n"
        ));
        out.push_str(&format!(
            "  return decodeEvent(MANIFEST, \"{}\", bytes);\n}}\n\n",
            e.name
        ));
    }

    out
}

/// A JSON string literal (with the quotes) for embedding Rust strings in TS.
fn json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

/// The TypeScript runtime implementing the wire format. It is emitted into
/// every generated stub so the client needs no runtime dependency.
const TS_RUNTIME: &str = r#"export interface AbiParam {
  name: string;
  type: string;
}

export interface AbiMethod {
  name: string;
  params: AbiParam[];
  returns: string;
  mutates_state: boolean;
}

export interface AbiEvent {
  name: string;
  topics: AbiParam[];
  data: AbiParam[];
}

export interface AbiManifest {
  methods: AbiMethod[];
  events: AbiEvent[];
}

/** Stable binary type tags (never renumbered). */
export const TAG_I64 = 0x01;
export const TAG_U64 = 0x02;
export const TAG_I32 = 0x03;
export const TAG_BOOL = 0x04;
export const TAG_BYTES = 0x05;
export const TAG_ADDRESS = 0x06;
export const TAG_STRING = 0x07;

function tagOf(typeName: string): number {
  switch (typeName.toLowerCase()) {
    case "i64": return TAG_I64;
    case "u64": return TAG_U64;
    case "i32": return TAG_I32;
    case "bool": return TAG_BOOL;
    case "bytes": return TAG_BYTES;
    case "address": return TAG_ADDRESS;
    case "string": return TAG_STRING;
    default: throw new Error(`unknown ABI type: ${typeName}`);
  }
}

function concat(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function u32le(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n >>> 0, true);
  return out;
}

function u32be(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n >>> 0, false);
  return out;
}

function i64be(v: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigInt64(0, BigInt.asIntN(64, v), false);
  return out;
}

function u64be(v: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt.asUintN(64, v), false);
  return out;
}

function i32be(v: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setInt32(0, v | 0, false);
  return out;
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

/** Encode one typed value: type tag + payload. */
export function encodeValue(typeName: string, value: AbiValue): Uint8Array {
  const tag = tagOf(typeName);
  switch (typeName.toLowerCase()) {
    case "i64":
      return concat([new Uint8Array([tag]), i64be(value as bigint)]);
    case "u64":
      return concat([new Uint8Array([tag]), u64be(value as bigint)]);
    case "i32":
      return concat([new Uint8Array([tag]), i32be(value as number)]);
    case "bool":
      return concat([new Uint8Array([tag]), new Uint8Array([value ? 1 : 0])]);
    case "bytes": {
      const bytes = value as Uint8Array;
      return concat([new Uint8Array([tag]), u32le(bytes.length), bytes]);
    }
    case "address": {
      const bytes = value as Uint8Array;
      if (bytes.length !== 32) throw new Error("an address must be 32 bytes");
      return concat([new Uint8Array([tag]), bytes]);
    }
    case "string": {
      const bytes = utf8(value as string);
      return concat([new Uint8Array([tag]), u32le(bytes.length), bytes]);
    }
    default:
      throw new Error(`unknown ABI type: ${typeName}`);
  }
}

/** Encode the arguments of a call: u32-le count + one tagged value each. */
export function encodeArgs(method: AbiMethod, args: AbiValue[]): Uint8Array {
  if (method.params.length !== args.length) {
    throw new Error(
      `${method.name} expects ${method.params.length} argument(s), got ${args.length}`,
    );
  }
  const parts: Uint8Array[] = [u32le(args.length)];
  method.params.forEach((p, i) => parts.push(encodeValue(p.type, args[i])));
  return concat(parts);
}

/** 4-byte method selector: sha256(name)[0..4] as u32-le. */
export async function methodSelector(name: string): Promise<Uint8Array> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(name)),
  );
  return digest.slice(0, 4);
}

/** Encode a full call payload: selector + arguments. */
export async function encodeCall(
  abi: AbiManifest,
  methodName: string,
  args: AbiValue[],
): Promise<Uint8Array> {
  const method = abi.methods.find((m) => m.name === methodName);
  if (!method) throw new Error(`unknown method: ${methodName}`);
  return concat([await methodSelector(methodName), encodeArgs(method, args)]);
}

/** Decode the arguments of a call. */
export function decodeArgs(method: AbiMethod, bytes: Uint8Array): AbiValue[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let off = 0;
  const count = view.getUint32(off, true);
  off += 4;
  if (count !== method.params.length) {
    throw new Error(
      `${method.name} expects ${method.params.length} argument(s), got ${count}`,
    );
  }
  const out: AbiValue[] = [];
  for (const p of method.params) {
    const tag = bytes[off++];
    if (tag !== tagOf(p.type)) {
      throw new Error(`unexpected type tag 0x${tag.toString(16)} for ${p.name}`);
    }
    out.push(decodeValue(p.type, bytes, view, off));
    off += valueSize(p.type, bytes, view, off);
  }
  return out;
}

function valueSize(typeName: string, bytes: Uint8Array, view: DataView, off: number): number {
  switch (typeName.toLowerCase()) {
    case "i64":
    case "u64":
      return 8;
    case "i32":
      return 4;
    case "bool":
      return 1;
    case "address":
      return 32;
    case "bytes":
    case "string":
      return 4 + view.getUint32(off, true);
    default:
      throw new Error(`unknown ABI type: ${typeName}`);
  }
}

function decodeValue(
  typeName: string,
  bytes: Uint8Array,
  view: DataView,
  off: number,
): AbiValue {
  switch (typeName.toLowerCase()) {
    case "i64":
      return view.getBigInt64(off, false);
    case "u64":
      return view.getBigUint64(off, false);
    case "i32":
      return view.getInt32(off, false);
    case "bool":
      return bytes[off] !== 0;
    case "address":
      return bytes.slice(off, off + 32);
    case "bytes": {
      const len = view.getUint32(off, true);
      return bytes.slice(off + 4, off + 4 + len);
    }
    case "string": {
      const len = view.getUint32(off, true);
      return new TextDecoder().decode(bytes.slice(off + 4, off + 4 + len));
    }
    default:
      throw new Error(`unknown ABI type: ${typeName}`);
  }
}

/** Decode an event payload: topics first, then data. */
export function decodeEvent(
  abi: AbiManifest,
  eventName: string,
  bytes: Uint8Array,
): { topics: AbiValue[]; data: AbiValue[] } {
  const event = abi.events.find((e) => e.name === eventName);
  if (!event) throw new Error(`unknown event: ${eventName}`);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let off = 0;
  const readGroup = (params: AbiParam[]): AbiValue[] => {
    const count = view.getUint32(off, true);
    off += 4;
    if (count !== params.length) {
      throw new Error(
        `${eventName} expects ${params.length} field(s), got ${count}`,
      );
    }
    const out: AbiValue[] = [];
    for (const p of params) {
      const tag = bytes[off++];
      if (tag !== tagOf(p.type)) {
        throw new Error(`unexpected type tag 0x${tag.toString(16)} for ${p.name}`);
      }
      out.push(decodeValue(p.type, bytes, view, off));
      off += valueSize(p.type, bytes, view, off);
    }
    return out;
  };
  const topics = readGroup(event.topics);
  const data = readGroup(event.data);
  return { topics, data };
}

"#;

// Keep the unused-import lint quiet for the parameter types used above.
#[allow(dead_code)]
fn _unused(_: &AbiEvent, _: &AbiParam) {}
