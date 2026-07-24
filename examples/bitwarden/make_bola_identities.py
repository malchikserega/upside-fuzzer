#!/usr/bin/env python3
"""
make_bola_identities.py — register N distinct Bitwarden users and emit a
multi-identity auth file for cross-identity (BOLA/IDOR) fuzzing.

Why: BOLA detection needs at least TWO different authenticated principals so the
fuzzer can replay user A's request as user B and see if B is (wrongly) granted
access. The stock get_apikey.py only provisions a single hardcoded user, which is
enough for coverage but NOT for cross-identity access-control testing.

This is a faithful, parameterized port of get_apikey.py's register + token flow.

Usage:
  python3 make_bola_identities.py                       # user-a + user-b + guest
  python3 make_bola_identities.py -e alice@x.local -e bob@x.local
  python3 make_bola_identities.py -o auth.identities.json

Then run the fuzzer with:  -auth-file /auth/auth.identities.json -profile security
"""

import argparse
import base64
import json
import urllib.error
import urllib.parse
import urllib.request
import uuid

API_URL = "http://localhost:4000"
IDENTITY_URL = "http://localhost:33656"
PASSWORD = "Password123!"
DUMMY_HASH = base64.b64encode(PASSWORD.encode()).decode()


def _post(url, data, headers, form=False):
    body = (
        urllib.parse.urlencode(data).encode("utf-8")
        if form
        else json.dumps(data).encode("utf-8")
    )
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req) as resp:
        return resp.status, resp.read().decode("utf-8")


def register_and_get_token(email):
    """Register (idempotently) and return an OAuth access token for `email`."""
    # 1. Verification email (may return a token, or 204 if verification is off).
    email_token = None
    try:
        status, body = _post(
            f"{IDENTITY_URL}/accounts/register/send-verification-email",
            {"email": email, "name": "Fuzzer"},
            {"Content-Type": "application/json"},
        )
        if status == 200 and body:
            email_token = body.strip().strip('"')
    except urllib.error.HTTPError as e:
        print(f"  [{email}] verification request failed: {e.code} (continuing)")

    # 2. Finish registration (400 is fine if the user already exists).
    reg = {
        "email": email,
        "masterPasswordHash": DUMMY_HASH,
        "masterPasswordHint": "test",
        "kdf": 0,
        "kdfIterations": 600000,
        "userSymmetricKey": "dummy_symmetric_key",
        "userAsymmetricKeys": {"publicKey": "dummy_pub", "encryptedPrivateKey": "dummy_priv"},
    }
    if email_token:
        reg["emailVerificationToken"] = email_token
    try:
        _post(f"{IDENTITY_URL}/accounts/register/finish", reg, {"Content-Type": "application/json"})
        print(f"  [{email}] registered")
    except urllib.error.HTTPError as e:
        print(f"  [{email}] register/finish -> {e.code} (likely already exists, continuing)")

    # 3. OAuth password grant -> access token.
    try:
        status, body = _post(
            f"{IDENTITY_URL}/connect/token",
            {
                "grant_type": "password",
                "username": email,
                "password": DUMMY_HASH,
                "scope": "api offline_access",
                "client_id": "web",
                "deviceIdentifier": str(uuid.uuid4()),
                "deviceName": "Fuzzer",
                "deviceType": "9",
            },
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "Bitwarden-Client-Version": "2024.1.0",
                "Device-Type": "9",
            },
            form=True,
        )
        token = json.loads(body).get("access_token")
        if token:
            print(f"  [{email}] token acquired ({token[:12]}...)")
            return token
        print(f"  [{email}] no access_token in response: {body[:200]}")
    except urllib.error.HTTPError as e:
        print(f"  [{email}] token request failed: {e.code} {e.read().decode()[:200]}")
    return None


def main():
    ap = argparse.ArgumentParser(description="Provision multi-identity auth file for BOLA fuzzing.")
    ap.add_argument(
        "-e", "--email", action="append", dest="emails",
        help="User email (repeatable). Default: user-a@bitwarden.local user-b@bitwarden.local",
    )
    ap.add_argument("-o", "--out", default="auth.identities.json", help="Output auth file path")
    args = ap.parse_args()

    emails = args.emails or ["user-a@bitwarden.local", "user-b@bitwarden.local"]
    if len(emails) < 2:
        print("WARNING: BOLA needs at least 2 distinct users; you supplied 1.")

    identities = []
    for i, email in enumerate(emails):
        print(f"Provisioning {email} ...")
        token = register_and_get_token(email)
        if not token:
            print(f"  SKIP {email}: could not obtain a token")
            continue
        identities.append({
            "name": email.split("@")[0],   # e.g. "user-a"
            "jwt": token,
            "weight": 2.0 if i == 0 else 1.5,
        })

    # Anonymous identity so auth-bypass / broken-auth probes have a no-cred principal.
    identities.append({"name": "guest", "weight": 0.3})

    real = [x for x in identities if x["name"] != "guest"]
    if len(real) < 2:
        print(f"\nWARNING: only {len(real)} authenticated identity provisioned — "
              "BOLA cross-user detection needs 2+. Auth-bypass will still work via guest.")

    with open(args.out, "w") as f:
        json.dump({"version": "1", "identities": identities}, f, indent=2)
    print(f"\nWrote {args.out} with {len(real)} authenticated identities + guest.")
    print("Mount it into the fuzzer:  -v \"$PWD/%s:/auth/auth.identities.json:ro\"" % args.out)


if __name__ == "__main__":
    main()
