import urllib.request
import urllib.error
import urllib.parse
import json
import base64
import uuid

API_URL = "http://localhost:4000"
IDENTITY_URL = "http://localhost:33656"

EMAIL = "admin@bitwarden.local"
PASSWORD = "Password123!"

# Bitwarden expects a master password hash, not plaintext
# For testing, we just supply a dummy hash (e.g. PBKDF2 string or random base64)
# since we will use the same string for /connect/token
DUMMY_HASH = base64.b64encode(PASSWORD.encode()).decode()

print("Sending verification email request...")
verify_data = json.dumps({"email": EMAIL, "name": "Fuzzer"}).encode('utf-8')
req_verify = urllib.request.Request(
    f"{IDENTITY_URL}/accounts/register/send-verification-email",
    data=verify_data,
    headers={"Content-Type": "application/json"},
    method="POST"
)

email_token = None
try:
    with urllib.request.urlopen(req_verify) as response:
        # It might return Ok(token) string or json
        if response.status == 200:
            resp_body = response.read().decode('utf-8').strip('"')
            print(f"Got verification token: {resp_body}")
            email_token = resp_body
        else:
            print("No token returned (204 No Content). Email verification might be enabled.")
except urllib.error.HTTPError as e:
    print(f"Verification request failed: {e.code}")

print("Registering user via API...")
reg_data = {
    "email": EMAIL,
    "masterPasswordHash": DUMMY_HASH,
    "masterPasswordHint": "test",
    "kdf": 0,
    "kdfIterations": 600000,
    "userSymmetricKey": "dummy_symmetric_key",
    "userAsymmetricKeys": {
        "publicKey": "dummy_pub",
        "encryptedPrivateKey": "dummy_priv"
    }
}
if email_token:
    reg_data["emailVerificationToken"] = email_token

reg_bytes = json.dumps(reg_data).encode('utf-8')

print("Sending /accounts/register/finish")
req = urllib.request.Request(f"{IDENTITY_URL}/accounts/register/finish", data=reg_bytes, headers={"Content-Type": "application/json"}, method="POST")
try:
    with urllib.request.urlopen(req) as resp:
        print("Registration via /finish successful.")
except urllib.error.HTTPError as e:
    print(f"Fallback registration failed: {e.code}")
    print(e.read().decode())

print("Requesting OAuth Token...")
token_data = urllib.parse.urlencode({
    "grant_type": "password",
    "username": EMAIL,
    "password": DUMMY_HASH,
    "scope": "api offline_access",
    "client_id": "web",
    "deviceIdentifier": str(uuid.uuid4()),
    "deviceName": "Fuzzer",
    "deviceType": "9"
}).encode('utf-8')

req = urllib.request.Request(
    f"{IDENTITY_URL}/connect/token",
    data=token_data,
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "Bitwarden-Client-Version": "2024.1.0",
        "Device-Type": "9"
    },
    method="POST"
)
try:
    with urllib.request.urlopen(req) as response:
        res_json = json.loads(response.read().decode('utf-8'))
        token = res_json.get("access_token")
        if token:
            print(f"Generated Token: {token[:15]}...")
            with open("fuzzer.env", "w") as f:
                f.write(f"AUTH_TOKEN={token}\n")
            print("Saved to fuzzer.env")
        else:
            print("No access_token in response.")
            print(res_json)
except urllib.error.HTTPError as e:
    print(f"Token generation failed: {e.code}")
    print(e.read().decode())
