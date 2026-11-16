#!/usr/bin/env bash
# check_import_graph.sh — Stage 1 import-graph boundary guard
# (docs/specs/CRATE_ISOLATION_PLAN.md & AGENTS.md §2).
#
# Enforces:
#   1. Core consensus/state/sharding modules in stellereum/src/
#      (consensus, consensus_net, sharding, state_engine, runtime, mempool,
#      staking, xshard2pc, chain, sync — both single .rs files and directory
#      modules) may NOT import from edge/UI/wallet modules
#      (rpc, explorer, wallet, wallet_signing, light_client_cli, cli, node),
#      ignoring comments, docstrings, string literals, and #[cfg(test)] blocks
#      (unless explicitly allowlisted below).
#   2. No crate or Rust source file in the repository imports or depends on the
#      stale diverged copies `stellereum_head` or `w8` (AGENTS.md §2).
#
# Exit 0 on pass; exit 1 with diagnostics on any forbidden import.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[import-graph] FAIL: python3 is required to run this check" >&2
  exit 1
fi

exec python3 - "$ROOT" <<'PY'
import glob
import os
import re
import sys

ROOT = sys.argv[1]
SRC_ROOT = os.path.join(ROOT, "stellereum", "src")

CORE_MODULES = [
    "consensus",
    "consensus_net",
    "sharding",
    "state_engine",
    "runtime",
    "mempool",
    "staking",
    "xshard2pc",
    "chain",
    "sync",
]

EDGE_MODULES = [
    "rpc",
    "explorer",
    "wallet",
    "wallet_signing",
    "light_client_cli",
    "cli",
    "node",
]

STALE_CRATES = ["stellereum_head", "w8"]

# Explicit allowlist of documented pre-existing adapter/test bridges if needed.
# Format: ("stellereum/src/<relpath>", "<edge_module>")
ALLOWLIST = set()

EDGE_RE_ALT = "|".join(re.escape(m) for m in EDGE_MODULES)
STALE_RE = re.compile(r"\b(" + "|".join(re.escape(c) for c in STALE_CRATES) + r")\b")

# Match qualified paths or module declarations targeting an edge module.
QUALIFIED_PATH_RE = re.compile(
    rf"(?<![.\w])(?:crate|super|self|stellereum)\s*::\s*({EDGE_RE_ALT})\b"
)
MOD_DECL_RE = re.compile(rf"(?<!\.)\bmod\s+({EDGE_RE_ALT})\b")
EXTERN_CRATE_RE = re.compile(rf"\bextern\s+crate\s+({EDGE_RE_ALT})\b")
USE_STMT_RE = re.compile(r"\b(?:pub(?:\s*\([^)]*\))?\s+)?use\s+([^;]+);")
USE_EDGE_DIRECT_RE = re.compile(
    rf"^(?:(?:crate|super|self|stellereum)\s*::\s*)?({EDGE_RE_ALT})(?:\s*::|\s+as\b|\s*$)"
)
USE_BRACE_RE = re.compile(
    rf"^(?:crate|super|self|stellereum)\s*::\s*\{{(.*)\}}$", re.DOTALL
)
USE_BRACE_ITEM_RE = re.compile(rf"(?:^|,)\s*(?:self\s*::\s*)?({EDGE_RE_ALT})\b")


def strip_rust_comments_and_strings(src: str):
    """
    Return (masked_code, path_attrs) where masked_code preserves line numbers
    (newlines kept) while replacing comments, string literals, raw strings,
    and char literals with spaces.
    path_attrs is a list of (lineno, attr_text) for #[path = "..."] attributes
    found outside comments.
    """
    out = []
    path_attrs = []
    i = 0
    n = len(src)
    line = 1

    while i < n:
        ch = src[i]

        # Line comment //
        if ch == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue

        # Block comment /* ... */ (supports nesting in Rust)
        if ch == "/" and i + 1 < n and src[i + 1] == "*":
            depth = 1
            i += 2
            while i < n and depth > 0:
                if src[i] == "/" and i + 1 < n and src[i + 1] == "*":
                    depth += 1
                    i += 2
                elif src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                    depth -= 1
                    i += 2
                else:
                    if src[i] == "\n":
                        out.append("\n")
                        line += 1
                    i += 1
            continue

        # Capture raw #[path = "..."] attribute before masking strings
        if ch == "#" and src[i : i + 2] == "#[":
            m = re.match(r'#\[\s*path\s*=\s*"([^"]*)"\s*\]', src[i:])
            if m:
                path_attrs.append((line, m.group(1)))

        # Raw string literals: r"...", r#"..."#, br#"..."#, cr#"..."#
        m_raw = re.match(r'(?:b|c)?r(#*)"', src[i:])
        if m_raw and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            hashes = m_raw.group(1)
            end_delim = '"' + hashes
            i += len(m_raw.group(0))
            out.append(" ")
            while i < n:
                if src.startswith(end_delim, i):
                    i += len(end_delim)
                    break
                if src[i] == "\n":
                    out.append("\n")
                    line += 1
                i += 1
            continue

        # Standard / byte / c string literal: "...", b"...", c"..."
        if ch == '"' or (
            ch in ("b", "c")
            and i + 1 < n
            and src[i + 1] == '"'
            and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_"))
        ):
            if ch != '"':
                i += 1
            i += 1
            out.append(" ")
            while i < n:
                if src[i] == "\\":
                    if i + 1 < n and src[i + 1] == "\n":
                        out.append("\n")
                        line += 1
                    i += 2
                elif src[i] == '"':
                    i += 1
                    break
                else:
                    if src[i] == "\n":
                        out.append("\n")
                        line += 1
                    i += 1
            continue

        # Char / byte char literal vs lifetime ('a / 'static)
        if ch == "'" or (
            ch == "b"
            and i + 1 < n
            and src[i + 1] == "'"
            and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_"))
        ):
            start = i
            if ch == "b":
                i += 1
            # Check escaped char literal: '\...' or single-char literal: 'x'
            if i + 1 < n and src[i + 1] == "\\":
                j = i + 2
                while j < n and src[j] != "'" and src[j] != "\n":
                    j += 1
                if j < n and src[j] == "'":
                    out.append(" ")
                    i = j + 1
                    continue
            elif i + 2 < n and src[i + 1] != "'" and src[i + 1] != "\n" and src[i + 2] == "'":
                out.append(" ")
                i += 3
                continue
            i = start

        if ch == "\n":
            line += 1
        out.append(ch)
        i += 1

    return "".join(out), path_attrs


def mask_cfg_test_blocks(code: str) -> tuple[str, set[str]]:
    """
    Replace #[cfg(test)] items (including mod tests { ... }, fn ... { ... },
    and semicolon-terminated items like #[cfg(test)] mod tests; / use ...;)
    with spaces (preserving newlines).
    Also returns any external mod names declared under #[cfg(test)] so
    directory subfiles mounted solely for tests are recognized.
    """
    n = len(code)
    chars = list(code)
    test_mods: set[str] = set()

    # Match #[cfg(test)] or #[cfg(all(test, ...))] etc. where test is a cfg predicate
    cfg_re = re.compile(r"#\[\s*cfg\s*\(([^]]*)\)\s*\]")

    pos = 0
    while pos < n:
        m = cfg_re.search(code, pos)
        if not m:
            break
        pred = m.group(1)
        # Only mask pure test-only cfgs (e.g. `test` or `all(test, ...)`),
        # NOT `any(test, debug_assertions)` which compiles in non-test debug builds.
        pred_norm = re.sub(r"\s+", "", pred)
        is_test_only = pred_norm == "test" or pred_norm.startswith("all(test,") or ",test)" in pred_norm and pred_norm.startswith("all(")
        if not is_test_only:
            pos = m.end()
            continue

        j = m.end()
        # Skip whitespace and any intervening attributes (#[...]) before the item
        while j < n:
            while j < n and chars[j].isspace():
                j += 1
            if j + 1 < n and chars[j] == "#" and chars[j + 1] == "[":
                bracket = 1
                j += 2
                while j < n and bracket > 0:
                    if chars[j] == "[":
                        bracket += 1
                    elif chars[j] == "]":
                        bracket -= 1
                    j += 1
            else:
                break

        # Check if this is an external `mod foo;` declaration
        tail = "".join(chars[j : min(n, j + 120)])
        m_ext_mod = re.match(r"(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", tail)
        if m_ext_mod:
            test_mods.add(m_ext_mod.group(1))

        # Blank out from #[cfg(test)] through the end of the item
        for k in range(m.start(), j):
            if chars[k] != "\n":
                chars[k] = " "

        brace_depth = 0
        saw_brace = False
        while j < n:
            c = chars[j]
            if c == "{":
                brace_depth += 1
                saw_brace = True
            elif c == "}":
                if brace_depth > 0:
                    brace_depth -= 1
                    if saw_brace and brace_depth == 0:
                        chars[j] = " "
                        j += 1
                        break
            elif c == ";" and not saw_brace:
                chars[j] = " "
                j += 1
                break
            if c != "\n":
                chars[j] = " "
            j += 1

        pos = j

    return "".join(chars), test_mods


def offset_to_line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def collect_core_files() -> list[tuple[str, str]]:
    """
    Collect (module_name, file_path) for every core module, supporting both
    single-file modules (`src/<mod>.rs`) and directory modules (`src/<mod>/**/*.rs`),
    excluding test-only submodules (`*/tests/*.rs` or `#[cfg(test)] mod foo;`).
    """
    files: list[tuple[str, str]] = []
    if not os.path.isdir(SRC_ROOT):
        return files

    for mod in CORE_MODULES:
        single = os.path.join(SRC_ROOT, f"{mod}.rs")
        mod_dir = os.path.join(SRC_ROOT, mod)
        if os.path.isfile(single):
            files.append((mod, single))
        if os.path.isdir(mod_dir):
            test_only_mods: set[str] = set()
            mod_rs = os.path.join(mod_dir, "mod.rs")
            if os.path.isfile(mod_rs):
                with open(mod_rs, encoding="utf-8", errors="replace") as fp:
                    cleaned, _ = strip_rust_comments_and_strings(fp.read())
                _, test_only_mods = mask_cfg_test_blocks(cleaned)

            for p in sorted(glob.glob(os.path.join(mod_dir, "**", "*.rs"), recursive=True)):
                rel_in_mod = os.path.relpath(p, mod_dir)
                parts = rel_in_mod.split(os.sep)
                stem = os.path.splitext(os.path.basename(p))[0]
                # Skip directory test modules (e.g. runtime/tests/*.rs) or #[cfg(test)] mod <name>;
                if "tests" in parts[:-1] or stem in test_only_mods:
                    continue
                files.append((mod, p))
    return files


def check_core_to_edge() -> tuple[list[str], int]:
    violations: list[str] = []
    core_files = collect_core_files()

    for _mod, path in core_files:
        rel_path = os.path.relpath(path, ROOT)
        with open(path, encoding="utf-8", errors="replace") as fp:
            raw = fp.read()

        stripped, path_attrs = strip_rust_comments_and_strings(raw)
        non_test_code, _ = mask_cfg_test_blocks(stripped)
        raw_lines = raw.splitlines()

        seen_at: set[tuple[int, str]] = set()

        def record(lineno: int, edge_mod: str, reason: str):
            if (rel_path, edge_mod) in ALLOWLIST:
                return
            key = (lineno, edge_mod)
            if key in seen_at:
                return
            seen_at.add(key)
            snippet = raw_lines[lineno - 1].strip() if 1 <= lineno <= len(raw_lines) else ""
            violations.append(
                f"[import-graph] FORBIDDEN core->edge import: {rel_path}:{lineno} "
                f"(imports `{edge_mod}` via {reason}): {snippet}"
            )

        # 1. Qualified paths (crate::rpc::..., stellereum::wallet::..., super::cli::...)
        for m in QUALIFIED_PATH_RE.finditer(non_test_code):
            lineno = offset_to_line(non_test_code, m.start())
            record(lineno, m.group(1), "qualified path")

        # 2. `use ...;` statements (single-line or multi-line)
        for m in USE_STMT_RE.finditer(non_test_code):
            stmt = m.group(1).strip()
            lineno = offset_to_line(non_test_code, m.start())
            dm = USE_EDGE_DIRECT_RE.match(stmt)
            if dm:
                record(lineno, dm.group(1), "use statement")
                continue
            bm = USE_BRACE_RE.match(stmt)
            if bm:
                for item in USE_BRACE_ITEM_RE.finditer(bm.group(1)):
                    record(lineno, item.group(1), "grouped use statement")

        # 3. `mod <edge>;` or `extern crate <edge>;`
        for m in MOD_DECL_RE.finditer(non_test_code):
            lineno = offset_to_line(non_test_code, m.start())
            record(lineno, m.group(1), "mod declaration")

        for m in EXTERN_CRATE_RE.finditer(non_test_code):
            lineno = offset_to_line(non_test_code, m.start())
            record(lineno, m.group(1), "extern crate")

        # 4. #[path = "..."] pointing into an edge module (outside #[cfg(test)])
        for lineno, attr_path in path_attrs:
            # Verify the attribute wasn't blanked out as #[cfg(test)]
            if lineno - 1 < len(non_test_code.splitlines()):
                attr_line_masked = non_test_code.splitlines()[lineno - 1]
                if not attr_line_masked.strip():
                    continue
            norm = attr_path.replace("\\", "/")
            for em in EDGE_MODULES:
                if re.search(rf"(?:^|/){re.escape(em)}(?:/|\.rs$)", norm):
                    record(lineno, em, f"#[path = \"{attr_path}\"]")

    return violations, len(core_files)


def check_stale_trees() -> tuple[list[str], int]:
    violations: list[str] = []
    skip_dirs = {"target", ".archive", "node_modules", "explorer-site", ".git", "artifacts"}
    scanned = 0

    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            if not (fname.endswith(".rs") or fname == "Cargo.toml"):
                continue
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, ROOT)
            scanned += 1
            with open(full, encoding="utf-8", errors="replace") as fp:
                raw = fp.read()

            if fname == "Cargo.toml":
                for lineno, line in enumerate(raw.splitlines(), 1):
                    no_comment = line.split("#", 1)[0]
                    m = STALE_RE.search(no_comment)
                    if m:
                        violations.append(
                            f"[import-graph] FORBIDDEN stale reference (AGENTS.md §2): "
                            f"{rel}:{lineno} (`{m.group(1)}`): {line.strip()}"
                        )
            else:
                stripped, path_attrs = strip_rust_comments_and_strings(raw)
                raw_lines = raw.splitlines()
                for m in STALE_RE.finditer(stripped):
                    lineno = offset_to_line(stripped, m.start())
                    snippet = raw_lines[lineno - 1].strip() if 1 <= lineno <= len(raw_lines) else ""
                    violations.append(
                        f"[import-graph] FORBIDDEN stale crate/module reference (AGENTS.md §2): "
                        f"{rel}:{lineno} (`{m.group(1)}`): {snippet}"
                    )
                for lineno, attr_path in path_attrs:
                    m = STALE_RE.search(attr_path)
                    if m:
                        snippet = raw_lines[lineno - 1].strip() if 1 <= lineno <= len(raw_lines) else ""
                        violations.append(
                            f"[import-graph] FORBIDDEN stale #[path] reference (AGENTS.md §2): "
                            f"{rel}:{lineno} (`{m.group(1)}`): {snippet}"
                        )

    return violations, scanned


def main() -> int:
    core_violations, core_count = check_core_to_edge()
    stale_violations, stale_count = check_stale_trees()
    all_violations = core_violations + stale_violations

    if all_violations:
        for v in all_violations:
            print(v, file=sys.stderr)
        print(
            f"[import-graph] FAIL: {len(all_violations)} forbidden import(s) detected "
            f"(checked {core_count} core file(s), {stale_count} repo manifest/source file(s))",
            file=sys.stderr,
        )
        return 1

    print(
        f"[import-graph] PASS: 0 forbidden cross-domain imports "
        f"(checked {core_count} core file(s), {stale_count} repo manifest/source file(s))"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
PY
