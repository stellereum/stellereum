#!/usr/bin/env node
/**
 * Deterministic generator/verifier for TypeScript JSON-RPC method types.
 *
 * Parses the Rust JSON-RPC dispatch match arms in:
 *   - stellereum/src/rpc/eth.rs (`dispatch_eth`)
 *   - stellereum/src/rpc/contracts.rs (`dispatch_contracts_inner`)
 *   - stellereum/src/rpc/writes.rs (`dispatch_writes_inner`)
 *   - stellereum/src/rpc/reads.rs (`dispatch_reads`)
 *   - stellereum/src/native_api.rs (`dispatch`, delegated from `dispatch_reads`)
 *
 * Usage:
 *   node sdk-js/scripts/generate-rpc-types.mjs          # writes sdk-js/src/generated-rpc.ts
 *   node sdk-js/scripts/generate-rpc-types.mjs --check  # verifies committed file matches
 */

import fs from "node:fs";
import path from "node:path";

const SCRIPT_DIR = path.dirname(new URL(import.meta.url).pathname);
const SDK_DIR = path.resolve(SCRIPT_DIR, "..");
const REPO_ROOT = path.resolve(SDK_DIR, "..");
const OUTPUT_PATH = path.join(SDK_DIR, "src", "generated-rpc.ts");

const DISPATCH_SOURCES = [
  {
    relPath: "stellereum/src/rpc/eth.rs",
    fnName: "dispatch_eth",
  },
  {
    relPath: "stellereum/src/rpc/contracts.rs",
    fnName: "dispatch_contracts_inner",
  },
  {
    relPath: "stellereum/src/rpc/writes.rs",
    fnName: "dispatch_writes_inner",
  },
  {
    relPath: "stellereum/src/rpc/reads.rs",
    fnName: "dispatch_reads",
  },
  {
    relPath: "stellereum/src/native_api.rs",
    fnName: "dispatch",
  },
];

function isIdentStart(ch) {
  return (
    (ch >= "a" && ch <= "z") ||
    (ch >= "A" && ch <= "Z") ||
    ch === "_"
  );
}

function isIdentContinue(ch) {
  return isIdentStart(ch) || (ch >= "0" && ch <= "9");
}

function skipWhitespaceAndComments(src, pos) {
  const len = src.length;
  let i = pos;
  while (i < len) {
    const ch = src[i];
    if (ch === " " || ch === "\t" || ch === "\r" || ch === "\n") {
      i += 1;
      continue;
    }
    if (ch === "/" && src[i + 1] === "/") {
      i += 2;
      while (i < len && src[i] !== "\n") {
        i += 1;
      }
      continue;
    }
    if (ch === "/" && src[i + 1] === "*") {
      i += 2;
      let depth = 1;
      while (i < len && depth > 0) {
        if (src[i] === "/" && src[i + 1] === "*") {
          depth += 1;
          i += 2;
        } else if (src[i] === "*" && src[i + 1] === "/") {
          depth -= 1;
          i += 2;
        } else {
          i += 1;
        }
      }
      continue;
    }
    break;
  }
  return i;
}

/**
 * If `src` at `pos` starts a Rust string/raw-string/char literal, returns
 * `{ nextPos, stringValue }` (`stringValue` is non-null only for regular/raw
 * string literals, not char literals). Returns `null` otherwise.
 */
function tryConsumeLiteral(src, pos) {
  const len = src.length;
  const ch = src[pos];

  // Raw string: r"..." or r#"..."# (and br"..." / br#"..."#)
  if (
    (ch === "r" || (ch === "b" && src[pos + 1] === "r")) &&
    (pos === 0 || !isIdentContinue(src[pos - 1]))
  ) {
    let j = ch === "b" ? pos + 2 : pos + 1;
    let hashes = 0;
    while (j < len && src[j] === "#") {
      hashes += 1;
      j += 1;
    }
    if (src[j] === '"') {
      j += 1;
      const start = j;
      while (j < len) {
        if (src[j] === '"') {
          let matched = 0;
          while (matched < hashes && src[j + 1 + matched] === "#") {
            matched += 1;
          }
          if (matched === hashes) {
            return {
              nextPos: j + 1 + hashes,
              stringValue: src.slice(start, j),
            };
          }
        }
        j += 1;
      }
      throw new Error(`Unterminated raw string literal at offset ${pos}`);
    }
  }

  // Regular or byte string: "..." / b"..."
  if (
    ch === '"' ||
    (ch === "b" &&
      src[pos + 1] === '"' &&
      (pos === 0 || !isIdentContinue(src[pos - 1])))
  ) {
    let j = ch === "b" ? pos + 2 : pos + 1;
    let value = "";
    while (j < len) {
      const c = src[j];
      if (c === "\\") {
        if (j + 1 >= len) {
          throw new Error(`Unterminated escape in string literal at offset ${pos}`);
        }
        value += src[j + 1];
        j += 2;
        continue;
      }
      if (c === '"') {
        return { nextPos: j + 1, stringValue: value };
      }
      value += c;
      j += 1;
    }
    throw new Error(`Unterminated string literal at offset ${pos}`);
  }

  // Char literal ('a', '\'', '\x7f', '\u{1234}') vs lifetime/label ('a, 'loop:)
  if (ch === "'") {
    if (src[pos + 1] === "\\") {
      let j = pos + 2;
      if (j < len) j += 1;
      while (j < len && src[j] !== "'" && src[j] !== "\n") {
        j += 1;
      }
      if (src[j] === "'") {
        return { nextPos: j + 1, stringValue: null };
      }
    } else if (pos + 2 < len && src[pos + 1] !== "'" && src[pos + 2] === "'") {
      return { nextPos: pos + 3, stringValue: null };
    }
  }

  return null;
}

function readIdent(src, pos) {
  let j = pos;
  while (j < src.length && isIdentContinue(src[j])) {
    j += 1;
  }
  return { ident: src.slice(pos, j), nextPos: j };
}

/**
 * Find the opening `{` of `fn <fnName>(...)` body, then locate `match method {`
 * inside it and extract all string literal patterns from top-level match arms.
 */
function extractMethodsFromFn(src, fnName, relPath) {
  const fnRegex = new RegExp(`\\bfn\\s+${fnName}\\s*\\(`);
  const fnMatch = fnRegex.exec(src);
  if (!fnMatch) {
    throw new Error(`Could not find function ${fnName} in ${relPath}`);
  }

  // Advance past parameter list `(...)` and return type to the function body `{`
  let i = fnMatch.index + fnMatch[0].length - 1; // at '('
  let parenDepth = 0;
  while (i < src.length) {
    i = skipWhitespaceAndComments(src, i);
    const lit = tryConsumeLiteral(src, i);
    if (lit) {
      i = lit.nextPos;
      continue;
    }
    if (src[i] === "(") {
      parenDepth += 1;
    } else if (src[i] === ")") {
      parenDepth -= 1;
      if (parenDepth === 0) {
        i += 1;
        break;
      }
    }
    i += 1;
  }

  // Find function opening `{`
  let fnBodyStart = -1;
  while (i < src.length) {
    i = skipWhitespaceAndComments(src, i);
    const lit = tryConsumeLiteral(src, i);
    if (lit) {
      i = lit.nextPos;
      continue;
    }
    if (src[i] === "{") {
      fnBodyStart = i + 1;
      break;
    }
    i += 1;
  }
  if (fnBodyStart === -1) {
    throw new Error(`Could not find body of ${fnName} in ${relPath}`);
  }

  // Locate `match method {` inside the function body
  i = fnBodyStart;
  let fnBraceDepth = 1;
  let matchStart = -1;
  while (i < src.length && fnBraceDepth > 0) {
    i = skipWhitespaceAndComments(src, i);
    if (i >= src.length) break;
    const lit = tryConsumeLiteral(src, i);
    if (lit) {
      i = lit.nextPos;
      continue;
    }
    if (src[i] === "{") {
      fnBraceDepth += 1;
      i += 1;
      continue;
    }
    if (src[i] === "}") {
      fnBraceDepth -= 1;
      i += 1;
      continue;
    }
    if (isIdentStart(src[i]) && (i === 0 || !isIdentContinue(src[i - 1]))) {
      const { ident, nextPos } = readIdent(src, i);
      if (ident === "match") {
        const afterMatch = skipWhitespaceAndComments(src, nextPos);
        if (isIdentStart(src[afterMatch])) {
          const scrutinee = readIdent(src, afterMatch);
          if (scrutinee.ident === "method") {
            const afterScrutinee = skipWhitespaceAndComments(src, scrutinee.nextPos);
            if (src[afterScrutinee] === "{") {
              matchStart = afterScrutinee + 1;
              break;
            }
          }
        }
      }
      i = nextPos;
      continue;
    }
    i += 1;
  }

  if (matchStart === -1) {
    throw new Error(`Could not find \`match method {\` inside ${fnName} in ${relPath}`);
  }

  // Parse arms of `match method { ... }`
  const methods = [];
  let braceDepth = 1;
  let armParenDepth = 0;
  let bracketDepth = 0;
  let inPattern = true;
  let inGuard = false;
  i = matchStart;

  while (i < src.length && braceDepth > 0) {
    i = skipWhitespaceAndComments(src, i);
    if (i >= src.length) break;

    const lit = tryConsumeLiteral(src, i);
    if (lit) {
      if (
        inPattern &&
        !inGuard &&
        braceDepth === 1 &&
        armParenDepth === 0 &&
        bracketDepth === 0 &&
        lit.stringValue !== null
      ) {
        methods.push(lit.stringValue);
      }
      i = lit.nextPos;
      continue;
    }

    if (inPattern) {
      if (
        braceDepth === 1 &&
        armParenDepth === 0 &&
        bracketDepth === 0 &&
        src[i] === "=" &&
        src[i + 1] === ">"
      ) {
        inPattern = false;
        inGuard = false;
        i += 2;
        continue;
      }
      if (
        braceDepth === 1 &&
        armParenDepth === 0 &&
        bracketDepth === 0 &&
        isIdentStart(src[i]) &&
        (i === 0 || !isIdentContinue(src[i - 1]))
      ) {
        const { ident, nextPos } = readIdent(src, i);
        if (ident === "if") {
          inGuard = true;
        }
        i = nextPos;
        continue;
      }
      if (src[i] === "{") {
        braceDepth += 1;
      } else if (src[i] === "}") {
        braceDepth -= 1;
        if (braceDepth === 0) {
          i += 1;
          break;
        }
      } else if (src[i] === "(") {
        armParenDepth += 1;
      } else if (src[i] === ")") {
        armParenDepth -= 1;
      } else if (src[i] === "[") {
        bracketDepth += 1;
      } else if (src[i] === "]") {
        bracketDepth -= 1;
      }
      i += 1;
      continue;
    }

    // Inside arm body (`!inPattern`)
    const ch = src[i];
    if (ch === "{") {
      braceDepth += 1;
      i += 1;
    } else if (ch === "}") {
      braceDepth -= 1;
      i += 1;
      if (braceDepth === 0) {
        break;
      }
      if (braceDepth === 1 && armParenDepth === 0 && bracketDepth === 0) {
        const nextTokPos = skipWhitespaceAndComments(src, i);
        let continuesExpr = false;
        if (src[nextTokPos] === ".") {
          continuesExpr = true;
        } else if (isIdentStart(src[nextTokPos])) {
          const { ident } = readIdent(src, nextTokPos);
          if (ident === "else") {
            continuesExpr = true;
          }
        }
        if (!continuesExpr) {
          inPattern = true;
        }
      }
    } else if (ch === "(") {
      armParenDepth += 1;
      i += 1;
    } else if (ch === ")") {
      armParenDepth -= 1;
      i += 1;
    } else if (ch === "[") {
      bracketDepth += 1;
      i += 1;
    } else if (ch === "]") {
      bracketDepth -= 1;
      i += 1;
    } else if (
      ch === "," &&
      braceDepth === 1 &&
      armParenDepth === 0 &&
      bracketDepth === 0
    ) {
      inPattern = true;
      i += 1;
    } else {
      i += 1;
    }
  }

  if (braceDepth !== 0) {
    throw new Error(`Unbalanced braces while parsing ${fnName} in ${relPath}`);
  }

  return methods;
}

function collectAllMethods() {
  const all = new Set();

  for (const spec of DISPATCH_SOURCES) {
    const absPath = path.join(REPO_ROOT, spec.relPath);
    const src = fs.readFileSync(absPath, "utf8");
    const extracted = extractMethodsFromFn(src, spec.fnName, spec.relPath);
    for (const m of extracted) {
      if (
        !m.startsWith("stell_") &&
        !m.startsWith("eth_") &&
        !m.startsWith("net_") &&
        !m.startsWith("web3_")
      ) {
        throw new Error(
          `Unexpected RPC method prefix "${m}" in ${spec.relPath}:${spec.fnName}`,
        );
      }
      all.add(m);
    }
  }

  const sortedAll = [...all].sort();
  const stell = sortedAll.filter((m) => m.startsWith("stell_"));
  const eth = sortedAll.filter((m) => m.startsWith("eth_"));
  const net = sortedAll.filter((m) => m.startsWith("net_"));
  const web3 = sortedAll.filter((m) => m.startsWith("web3_"));

  return {
    all: sortedAll,
    stell,
    eth,
    net,
    web3,
  };
}

function formatStringTuple(name, items) {
  const lines = [`export const ${name} = [`];
  for (const item of items) {
    lines.push(`  "${item}",`);
  }
  lines.push("] as const;");
  return lines.join("\n");
}

function renderTypeScript(methods) {
  const sourceList = DISPATCH_SOURCES.map(
    (s) => ` *   - ${s.relPath} (${s.fnName})`,
  ).join("\n");

  return [
    "/**",
    " * AUTO-GENERATED FILE — DO NOT EDIT BY HAND.",
    " *",
    " * Generated by `sdk-js/scripts/generate-rpc-types.mjs` from the Rust",
    " * JSON-RPC dispatch arms in:",
    sourceList,
    " *",
    " * Regenerate with: `npm run generate:rpc-types` (inside `sdk-js/`).",
    " * Verify sync with: `npm run check:rpc-types` (inside `sdk-js/`).",
    " */",
    "",
    formatStringTuple("STELL_RPC_METHODS", methods.stell),
    "",
    formatStringTuple("ETH_RPC_METHODS", methods.eth),
    "",
    formatStringTuple("NET_RPC_METHODS", methods.net),
    "",
    formatStringTuple("WEB3_RPC_METHODS", methods.web3),
    "",
    formatStringTuple("NODE_RPC_METHODS", methods.all),
    "",
    "export type StellRpcMethod = (typeof STELL_RPC_METHODS)[number];",
    "export type EthRpcMethod = (typeof ETH_RPC_METHODS)[number];",
    "export type NetRpcMethod = (typeof NET_RPC_METHODS)[number];",
    "export type Web3RpcMethod = (typeof WEB3_RPC_METHODS)[number];",
    "export type NodeRpcMethod = (typeof NODE_RPC_METHODS)[number];",
    "",
  ].join("\n");
}

function buildDiffMessage(expected, actual) {
  const expectedLines = expected.split("\n");
  const actualLines = actual.split("\n");
  const expectedSet = new Set(expectedLines);
  const actualSet = new Set(actualLines);

  const missingInCommitted = expectedLines.filter((l) => !actualSet.has(l));
  const extraInCommitted = actualLines.filter((l) => !expectedSet.has(l));

  const parts = [
    `rpc-types out of sync: ${path.relative(REPO_ROOT, OUTPUT_PATH)} does not match Rust RPC dispatch.`,
    "Run `npm run generate:rpc-types` (inside `sdk-js/`) to update it.",
  ];

  if (missingInCommitted.length > 0) {
    parts.push("Missing lines in committed file:");
    for (const line of missingInCommitted.slice(0, 20)) {
      parts.push(`  + ${line}`);
    }
    if (missingInCommitted.length > 20) {
      parts.push(`  ... (${missingInCommitted.length - 20} more)`);
    }
  }
  if (extraInCommitted.length > 0) {
    parts.push("Extra/stale lines in committed file:");
    for (const line of extraInCommitted.slice(0, 20)) {
      parts.push(`  - ${line}`);
    }
    if (extraInCommitted.length > 20) {
      parts.push(`  ... (${extraInCommitted.length - 20} more)`);
    }
  }
  if (missingInCommitted.length === 0 && extraInCommitted.length === 0) {
    const maxLen = Math.max(expectedLines.length, actualLines.length);
    for (let idx = 0; idx < maxLen; idx += 1) {
      if (expectedLines[idx] !== actualLines[idx]) {
        parts.push(
          `First difference at line ${idx + 1}:\n  expected: ${JSON.stringify(expectedLines[idx])}\n  actual:   ${JSON.stringify(actualLines[idx])}`,
        );
        break;
      }
    }
  }

  return parts.join("\n");
}

function main() {
  const args = new Set(process.argv.slice(2));
  const checkMode = args.has("--check");
  for (const arg of args) {
    if (arg !== "--check") {
      console.error(`Unknown argument: ${arg}`);
      process.exit(2);
    }
  }

  const methods = collectAllMethods();
  const generated = renderTypeScript(methods);

  if (checkMode) {
    if (!fs.existsSync(OUTPUT_PATH)) {
      console.error(
        `rpc-types check failed: ${path.relative(REPO_ROOT, OUTPUT_PATH)} does not exist.\n` +
          "Run `npm run generate:rpc-types` (inside `sdk-js/`) to generate it.",
      );
      process.exit(1);
    }
    const committed = fs.readFileSync(OUTPUT_PATH, "utf8");
    if (committed !== generated) {
      console.error(buildDiffMessage(generated, committed));
      process.exit(1);
    }
    console.log(
      `rpc-types: in sync (stell=${methods.stell.length}, eth=${methods.eth.length}, net=${methods.net.length}, web3=${methods.web3.length}, total=${methods.all.length})`,
    );
    return;
  }

  fs.writeFileSync(OUTPUT_PATH, generated, "utf8");
  console.log(
    `generated ${path.relative(REPO_ROOT, OUTPUT_PATH)} (stell=${methods.stell.length}, eth=${methods.eth.length}, net=${methods.net.length}, web3=${methods.web3.length}, total=${methods.all.length})`,
  );
}

main();
