#!/usr/bin/env python3
"""shared_judge.py -- BENCHMARK_PLAN.md §8/§21 task #3: a single taxonomy +
dedup pass applied uniformly to BOTH tools' raw findings, so neither tool's
own native classification decides the comparison (§8: "do not use each
tool's native classification for the comparison").

Clustering is a direct Python port of void/go/cluster.go::rootCauseClusterKey
(normalized exception message + first *application* stack frame, falling
back to (method, route-template, status) when no exception detail is
available), applied here to RESTler's raw bug-bucket captures too -- RESTler
never computes this itself, and per §8 that's exactly the point: both tools'
raw findings go through the identical clustering logic.

Scope (honest): this script performs classification + dedup from the raw
artifacts each tool already wrote. It does NOT perform the full §8
validation pipeline (replay-based reproduction against a freshly-reset
target, minimization, `reproducibility_rate`) -- that needs a live target
and is a separate step layered on top of this script's output, not
reimplemented here.

Usage:
  shared_judge.py \
    --upsidefuzz-jsonl raw/<experiment>/<run_id>/unique-crashes.jsonl \
    --restler-bug-buckets restler_bin/restler/Test/RestlerResults/experiment<N>/bug_buckets \
    --run-id <run_id> --tool upsidefuzz \
    --out raw/<experiment>/<run_id>/confirmed_bug.json

Run once per run_id, pointing at whichever artifact that run produced (only
one of --upsidefuzz-jsonl / --restler-bug-buckets is required per invocation
-- the harness calls this once per completed run, tagging --tool
accordingly, so cross-run analysis later groups by cluster_key across tools
without ever comparing tool-native labels).
"""
import argparse
import json
import re
import sys
from pathlib import Path

# --- Direct port of void/go/cluster.go's regexes and logic -----------------

RE_EXC_MSG_FIELD = re.compile(r'(?i)"exceptionMessage"\s*:\s*"((?:[^"\\]|\\.){0,300})"')
RE_FIRST_DOTNET_EXCEPTION = re.compile(r'((?:[A-Za-z0-9_]+\.)+[A-Za-z0-9_]*Exception)\s*:\s*([^\r\n]{0,300})')
RE_APP_STACK_FRAME = re.compile(r'(?:^|\s)at\s+((?:[A-Za-z0-9_]+\.)+[A-Za-z0-9_<>`]+)')
RE_QUOTED_IDENT = re.compile(r"'[^']*'")
RE_DBL_QUOTED = re.compile(r'"[^"]*"')
RE_GUID_ANY = re.compile(r'(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b')
RE_BASE64ISH = re.compile(r'\b[A-Za-z0-9+/_-]{16,}={0,2}\b')
RE_ANY_NUMBER = re.compile(r'\b\d+\b')
RE_WS = re.compile(r'\s+')

FRAMEWORK_FRAME_PREFIXES = (
    "system.", "microsoft.", "newtonsoft.", "swashbuckle.",
    "mediatr.", "automapper.", "serilog.", "polly.", "fluentvalidation.",
)


def extract_exception_message(body: str, exception_type: str, exception_msg: str) -> str:
    if exception_msg and exception_msg.strip():
        return exception_msg.strip()
    s = (body or "").strip()[:8192]
    if s:
        m = RE_EXC_MSG_FIELD.search(s)
        if m:
            try:
                decoded = json.loads('"' + m.group(1) + '"')
                if decoded.strip():
                    return decoded.strip()
            except Exception:  # noqa: BLE001
                pass
        m = RE_FIRST_DOTNET_EXCEPTION.search(s)
        if m:
            return m.group(1).strip() + ": " + m.group(2).strip()
    return (exception_type or "").strip()


def normalize_exception_message(msg: str) -> str:
    m = (msg or "").strip().lower()
    if not m:
        return ""
    m = RE_QUOTED_IDENT.sub("'x'", m)
    m = RE_DBL_QUOTED.sub('"x"', m)
    m = RE_GUID_ANY.sub("<guid>", m)
    m = RE_BASE64ISH.sub("<tok>", m)
    m = RE_ANY_NUMBER.sub("<n>", m)
    m = RE_WS.sub(" ", m).strip()
    return m[:160]


def extract_top_app_frame(body: str) -> str:
    s = (body or "")[:8192]
    for m in RE_APP_STACK_FRAME.finditer(s):
        frame = m.group(1).strip()
        low = frame.lower()
        if not any(low.startswith(p) for p in FRAMEWORK_FRAME_PREFIXES):
            return frame
    return ""


def coarsen_path_params(norm_path: str) -> str:
    for token in ("{uuid}", "{id}", "{int}", "{hex}", "{long}"):
        norm_path = norm_path.replace(token, "{param}")
    return norm_path


def normalize_endpoint_path(path: str) -> str:
    """Lightweight stand-in for void/go/utils.go::normalizeEndpointPath: strips
    query string and collapses digit/uuid-shaped segments to {param}. Not
    byte-for-byte identical to the Go version's full heuristics (long-hex,
    dashed-with-digit, etc.) -- close enough for cross-run clustering, since
    both tools' findings go through this SAME simplified pass."""
    path = path.split("?", 1)[0]
    segs = [s for s in path.split("/") if s != ""]
    out = []
    for s in segs:
        if re.fullmatch(r"[0-9]+", s) or re.fullmatch(
            r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", s
        ):
            out.append("{param}")
        else:
            out.append(s)
    return "/" + "/".join(out)


def root_cause_cluster_key(method: str, status: int, exception_type: str, exception_msg: str, body: str, norm_path: str):
    msg = extract_exception_message(body, exception_type, exception_msg)
    norm_msg = normalize_exception_message(msg)
    frame = extract_top_app_frame(body)

    if norm_msg:
        parts = ["ex", norm_msg]
        if frame:
            parts.append("@" + frame.lower())
        key = "|".join(parts)
        label = msg + ("  @ " + frame if frame else "")
        return key, label[:200], True, msg

    tmpl = coarsen_path_params(norm_path)
    key = f"ep|{method.upper()}|{status}|{tmpl}"
    label = f"{method.upper()} {tmpl} -> {status} (no exception detail)"
    return key, label, False, ""


def classify(resolved_exception_msg: str, oracle_tag: str, oracle_reasons=None) -> tuple:
    """Returns (bug_class, head_to_head_eligible). oracle_tag is UpsideFuzz's
    own access_control/injection marker when present (empty for RESTler,
    which structurally cannot produce these -- BENCHMARK_PLAN.md §2's
    capability-vs-head-to-head separation rule). resolved_exception_msg is
    whatever root_cause_cluster_key actually extracted (header field for
    UpsideFuzz in production mode, or a dev-mode body-parsed ".NET
    Exception: message" line for either tool) -- classification runs on
    that resolved text, not a possibly-empty raw field, so it works
    identically for both tools' inputs."""
    if oracle_tag == "injection":
        reasons = " ".join(oracle_reasons or []).lower()
        if "sqli" in reasons:
            return "injection_sqli", False
        if "ssti" in reasons:
            return "injection_ssti", False
        if "ssrf" in reasons:
            return "ssrf", False
        if "cmdi" in reasons:
            return "injection_cmdi", False
        return "injection_other", False
    if oracle_tag:
        mapping = {
            "bola": "IDOR/BOLA", "authbypass": "authz_bypass",
            "massassign": "mass_assignment", "differential": "authz_bypass",
        }
        return mapping.get(oracle_tag, "business_logic"), False
    et = (resolved_exception_msg or "").lower()
    if "argumentoutofrange" in et or "argumentexception" in et or "overflow" in et or "indexoutofrange" in et:
        return "numeric_boundary", True
    return "unhandled_exception", True


# --- Ingestion: UpsideFuzz ---------------------------------------------------

def load_upsidefuzz(path: Path, tool_label: str, run_id: str):
    candidates = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            method = row.get("method", "")
            status = row.get("status_code", 0)
            path_ = row.get("path", "")
            body = row.get("response_body", "")
            exc_type = row.get("exception_type", "")
            triage = row.get("triage", {}) or {}
            oracle_tag = triage.get("oracle", "") if row.get("access_control") or row.get("injection") else ""
            key, label, has_exc, resolved_msg = root_cause_cluster_key(method, status, exc_type, "", body, normalize_endpoint_path(path_))
            bug_class, h2h = classify(resolved_msg or exc_type, oracle_tag, triage.get("reasons", []))
            candidates.append({
                "candidate_id": row.get("signature", key),
                "run_id": run_id,
                "tool": tool_label,
                "method": method,
                "endpoint_template": normalize_endpoint_path(path_),
                "status": status,
                "cluster_key": key,
                "cluster_label": label,
                "has_exception_detail": has_exc,
                "bug_class": bug_class,
                "head_to_head_eligible": h2h,
                "native_classification_ignored": triage.get("classification", ""),
            })
    return candidates


# --- Ingestion: RESTler -------------------------------------------------------

RE_HTTP_STATUS_LINE = re.compile(r'HTTP/1\.[01]\s+(\d{3})')


def _extract_restler_body(raw_response: str) -> str:
    """RESTler's captured response text is raw HTTP (headers + chunked body).
    We don't need a real chunked-transfer-encoding decoder -- the exception
    text we're grepping for appears verbatim in the raw bytes regardless of
    chunk-size markers interleaved in it, so just search the whole blob."""
    return raw_response or ""


def load_restler(bug_buckets_dir: Path, tool_label: str, run_id: str):
    candidates = []
    for jf in sorted(bug_buckets_dir.glob("*.json")):
        if jf.name == "bug_buckets.json":
            continue  # aggregate summary, not a per-bug record
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict) or "request_sequence" not in data:
            continue
        method = data.get("verb", "")
        endpoint = data.get("endpoint", "")
        status = int(data.get("status_code", 0) or 0)
        seq = data.get("request_sequence", [])
        body = ""
        if seq:
            body = _extract_restler_body(seq[-1].get("response", ""))
        key, label, has_exc, resolved_msg = root_cause_cluster_key(method, status, "", "", body, normalize_endpoint_path(endpoint))
        bug_class, h2h = classify(resolved_msg, "")  # RESTler never carries an oracle tag
        candidates.append({
            "candidate_id": jf.stem,
            "run_id": run_id,
            "tool": tool_label,
            "method": method,
            "endpoint_template": normalize_endpoint_path(endpoint),
            "status": status,
            "cluster_key": key,
            "cluster_label": label,
            "has_exception_detail": has_exc,
            "bug_class": bug_class,
            "head_to_head_eligible": h2h,
            "native_classification_ignored": data.get("checker_name", ""),
        })
    return candidates


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--upsidefuzz-jsonl", default=None, help="Path to unique-crashes.jsonl / crashes.jsonl")
    ap.add_argument("--restler-bug-buckets", default=None, help="Path to a RESTler experiment's bug_buckets/ directory")
    ap.add_argument("--tool", required=True, choices=["upsidefuzz", "restler"])
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    if args.tool == "upsidefuzz":
        if not args.upsidefuzz_jsonl:
            print("--upsidefuzz-jsonl is required when --tool upsidefuzz", file=sys.stderr)
            sys.exit(2)
        candidates = load_upsidefuzz(Path(args.upsidefuzz_jsonl), args.tool, args.run_id)
    else:
        if not args.restler_bug_buckets:
            print("--restler-bug-buckets is required when --tool restler", file=sys.stderr)
            sys.exit(2)
        candidates = load_restler(Path(args.restler_bug_buckets), args.tool, args.run_id)

    # Dedup within this run by cluster_key -- headline counts use distinct
    # root causes (BENCHMARK_PLAN.md §8: "headline counts use distinct root
    # causes"), so collapse here and keep a representative + occurrence count.
    by_cluster = {}
    for c in candidates:
        k = c["cluster_key"]
        if k not in by_cluster:
            by_cluster[k] = {**c, "occurrence_count": 1}
        else:
            by_cluster[k]["occurrence_count"] += 1

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(list(by_cluster.values()), indent=2), encoding="utf-8")
    print(f"[shared_judge] {len(candidates)} raw candidates -> {len(by_cluster)} distinct root causes -> {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
