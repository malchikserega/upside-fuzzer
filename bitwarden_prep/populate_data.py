#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path


DEFAULT_API_URL = "http://localhost:4000"


def strip_bearer_prefix(value):
    raw = str(value or "").strip()
    parts = raw.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return raw


def set_header(headers, name, value):
    wanted = name.lower()
    for existing in list(headers):
        if existing.lower() == wanted:
            headers[existing] = value
            return
    headers[name] = value


def load_env_file(path):
    env = {}
    try:
        for line in Path(path).read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.strip().split("=", 1)
                env[key] = value.strip().strip('"').strip("'")
    except FileNotFoundError:
        return {}
    except Exception as exc:
        raise SystemExit(f"Could not read {path}: {exc}") from exc
    return env


def base_headers():
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def auth_headers_from_env(env):
    headers = base_headers()
    if env.get("AUTH_TOKEN"):
        token = strip_bearer_prefix(env["AUTH_TOKEN"])
        set_header(headers, "Authorization", f"Bearer {token}")
        return headers
    if env.get("AUTH_HEADERS_JSON"):
        headers.update(json.loads(env["AUTH_HEADERS_JSON"]))
        return headers
    if env.get("AUTH_HEADER") and ":" in env["AUTH_HEADER"]:
        name, value = env["AUTH_HEADER"].split(":", 1)
        set_header(headers, name.strip(), value.strip())
        return headers
    if env.get("AUTH_COOKIE"):
        set_header(headers, "Cookie", env["AUTH_COOKIE"])
        return headers
    return None


def auth_headers_from_identity(identity):
    headers = base_headers()

    for key, value in (identity.get("headers") or {}).items():
        if str(key).strip() and str(value).strip():
            set_header(headers, str(key).strip(), str(value).strip())

    jwt = identity.get("jwt") or identity.get("token")
    if jwt:
        set_header(headers, "Authorization", f"Bearer {strip_bearer_prefix(jwt)}")

    api_key = identity.get("api_key")
    api_key_env = str(identity.get("api_key_env") or "").strip()
    if not api_key and api_key_env:
        api_key = os.environ.get(api_key_env, "").strip()
        if not api_key:
            return None, f"api_key_env {api_key_env} is empty"
    if api_key:
        api_key_header = str(identity.get("api_key_header") or "X-Api-Key").strip()
        set_header(headers, api_key_header, str(api_key).strip())

    if identity.get("cookie"):
        set_header(headers, "Cookie", str(identity["cookie"]).strip())

    has_auth = any(
        key.lower() in ("authorization", "cookie")
        or "api-key" in key.lower()
        or "apikey" in key.lower()
        or "token" in key.lower()
        or "secret" in key.lower()
        for key in headers
    )
    if not has_auth:
        return None, "no auth material"
    return headers, ""


def parse_identity_items(raw):
    data = json.loads(raw)
    if isinstance(data, dict) and isinstance(data.get("identities"), list):
        for index, item in enumerate(data["identities"], 1):
            if isinstance(item, dict):
                yield f"id-{index}", item
        return
    if isinstance(data, list):
        for index, item in enumerate(data, 1):
            if isinstance(item, dict):
                yield f"id-{index}", item
        return
    if isinstance(data, dict):
        for key in sorted(data):
            item = data[key]
            if isinstance(item, dict):
                if not item.get("name"):
                    item = {**item, "name": key}
                yield key, item
        return
    raise ValueError("expected wrapper object, identity array, or identity object map")


def identities_from_auth_file(path):
    raw = Path(path).read_text()
    identities = []
    for default_name, item in parse_identity_items(raw):
        name = str(item.get("name") or default_name).strip()
        if not name:
            name = default_name
        headers, skip_reason = auth_headers_from_identity(item)
        if headers is None:
            print(f"Skipping identity {name!r}: {skip_reason}")
            continue
        identities.append({"name": name, "headers": headers})
    return identities


def identities_from_inline_json(raw):
    identities = []
    for default_name, item in parse_identity_items(raw):
        name = str(item.get("name") or default_name).strip() or default_name
        headers, skip_reason = auth_headers_from_identity(item)
        if headers is None:
            print(f"Skipping identity {name!r}: {skip_reason}")
            continue
        identities.append({"name": name, "headers": headers})
    return identities


def load_identities(args):
    auth_file = args.auth_file or os.environ.get("AUTH_FILE", "")
    if auth_file:
        path = Path(auth_file)
        if not path.exists():
            raise SystemExit(f"Auth file not found: {auth_file}")
        identities = identities_from_auth_file(path)
        if not identities:
            raise SystemExit(f"Auth file had no usable non-guest identities: {auth_file}")
        return identities, f"auth-file {path}"

    default_auth_file = Path("auth.identities.json")
    if default_auth_file.exists():
        identities = identities_from_auth_file(default_auth_file)
        if identities:
            return identities, f"auth-file {default_auth_file}"

    inline = os.environ.get("AUTH_IDENTITIES_JSON", "").strip()
    if inline:
        identities = identities_from_inline_json(inline)
        if identities:
            return identities, "AUTH_IDENTITIES_JSON"

    env = load_env_file(args.env_file)
    headers = auth_headers_from_env(env)
    if headers:
        return [{"name": "fuzzer-env-user", "headers": headers}], f"env-file {args.env_file}"

    raise SystemExit(
        "No usable auth found. Pass --auth-file auth.identities.json or run get_apikey.py to create fuzzer.env."
    )


def encrypted_value(identity_name, kind, index):
    seed = f"{identity_name}:{kind}:{index}".encode("utf-8")
    iv = hashlib.sha256(seed + b":iv").digest()[:16]
    ciphertext = hashlib.sha256(seed + b":ct").digest()[:16]
    return "0." + base64.b64encode(iv).decode("ascii") + "|" + base64.b64encode(ciphertext).decode("ascii")


def request_json(api_url, identity_name, headers, method, path, data, timeout, fail_fast):
    req = urllib.request.Request(
        f"{api_url}{path}",
        data=json.dumps(data).encode("utf-8") if data is not None else None,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read().decode("utf-8")
            return json.loads(resp_body) if resp_body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        print(f"[{identity_name}] {method} {path} failed: HTTP {exc.code} {body[:300]}")
        if fail_fast:
            raise
        return None
    except urllib.error.URLError as exc:
        print(f"[{identity_name}] {method} {path} failed: {exc}")
        if fail_fast:
            raise
        return None


def post(api_url, identity_name, headers, path, data, args):
    return request_json(api_url, identity_name, headers, "POST", path, data, args.timeout, args.fail_fast)


def populate_identity(api_url, identity, args):
    name = identity["name"]
    headers = identity["headers"]
    print(f"\n[{name}] Populating Bitwarden fake data...")

    result = {
        "identity": name,
        "folders": [],
        "ciphers": [],
        "sends": [],
    }

    if args.dry_run:
        print(f"[{name}] dry-run: would create {args.folders} folders, {args.ciphers} ciphers, {args.sends} sends")
        return result

    print(f"[{name}] Creating folders...")
    for index in range(args.folders):
        folder = post(api_url, name, headers, "/folders", {"name": encrypted_value(name, "folder", index)}, args)
        if folder and folder.get("id"):
            result["folders"].append(folder["id"])
            print(f"  -> Folder ID: {folder['id']}")

    print(f"[{name}] Creating ciphers...")
    for index in range(args.ciphers):
        folder_id = result["folders"][index % len(result["folders"])] if result["folders"] else None
        fake_enc = encrypted_value(name, "cipher", index)
        cipher_data = {
            "type": 1,
            "folderId": folder_id,
            "organizationId": None,
            "name": fake_enc,
            "notes": encrypted_value(name, "notes", index),
            "favorite": (index % 2 == 0),
            "login": {
                "uri": encrypted_value(name, "uri", index),
                "username": encrypted_value(name, "username", index),
                "password": encrypted_value(name, "password", index),
                "totp": encrypted_value(name, "totp", index),
                "passwordRevisionDate": None,
                "uris": [{"uri": fake_enc, "match": None}],
            },
        }
        cipher = post(api_url, name, headers, "/ciphers", cipher_data, args)
        if cipher and cipher.get("id"):
            result["ciphers"].append(cipher["id"])
            print(f"  -> Cipher ID: {cipher['id']}")

    print(f"[{name}] Creating sends...")
    future_date = (datetime.now(timezone.utc) + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for index in range(args.sends):
        send_data = {
            "type": 0,
            "name": encrypted_value(name, "send", index),
            "key": encrypted_value(name, "send-key", index),
            "text": {
                "text": encrypted_value(name, "send-text", index),
                "hidden": True,
            },
            "maxAccessCount": 10,
            "deletionDate": future_date,
            "expirationDate": future_date,
            "disabled": False,
            "hideEmail": False,
        }
        send = post(api_url, name, headers, "/sends", send_data, args)
        if send and send.get("id"):
            result["sends"].append(send["id"])
            print(f"  -> Send ID: {send['id']}")

    print(
        f"[{name}] Created folders={len(result['folders'])} "
        f"ciphers={len(result['ciphers'])} sends={len(result['sends'])}"
    )
    return result


def write_inventory(path, api_url, source, results):
    inventory = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "api_url": api_url,
        "auth_source": source,
        "note": "No auth secrets are stored here. IDs are grouped by identity for access-control triage.",
        "identities": results,
    }
    Path(path).write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    print(f"\nWrote populated object inventory: {path}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Populate a local Bitwarden test stand with fake encrypted vault data."
    )
    parser.add_argument("--api-url", default=os.environ.get("BITWARDEN_API_URL", DEFAULT_API_URL))
    parser.add_argument("--auth-file", default="", help="Void auth identities JSON file")
    parser.add_argument("--env-file", default="fuzzer.env", help="Fallback single-user fuzzer env file")
    parser.add_argument("--identity", action="append", default=[], help="Only populate matching identity name")
    parser.add_argument("--folders", type=int, default=3)
    parser.add_argument("--ciphers", type=int, default=15)
    parser.add_argument("--sends", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--output", default="populated-objects.json")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--fail-fast", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    identities, source = load_identities(args)

    wanted = {name.strip() for name in args.identity if name.strip()}
    if wanted:
        identities = [identity for identity in identities if identity["name"] in wanted]
        missing = wanted - {identity["name"] for identity in identities}
        if missing:
            raise SystemExit(f"Requested identities not found or not usable: {', '.join(sorted(missing))}")
    if not identities:
        raise SystemExit("No identities selected.")

    print(f"Auth source: {source}")
    print(f"API URL: {args.api_url}")
    print("Selected identities: " + ", ".join(identity["name"] for identity in identities))

    results = [populate_identity(args.api_url.rstrip("/"), identity, args) for identity in identities]
    if not args.dry_run:
        write_inventory(args.output, args.api_url.rstrip("/"), source, results)
    print("\nData population complete!")


if __name__ == "__main__":
    main()
