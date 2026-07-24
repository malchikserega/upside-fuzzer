import urllib.request
import urllib.error
import json
import base64

URL = "http://localhost:7777"
EMAIL = "admin@btcpayserver.local"
PASSWORD = "Password123!"

auth_string = f"{EMAIL}:{PASSWORD}"
b64_auth = base64.b64encode(auth_string.encode('ascii')).decode('ascii')
headers = {
    "Authorization": f"Basic {b64_auth}",
    "Content-Type": "application/json"
}

print("Generating API Key via Greenfield API...")
data = {
    "label": "FuzzerKey",
    "permissions": [
        "btcpay.server.canmodifyserversettings",
        "btcpay.store.canmodifystoresettings",
        "btcpay.store.cancreateinvoice",
        "btcpay.store.webhooks.canmodifywebhooks",
        "btcpay.store.canmanagepaymentrequests",
        "btcpay.user.canviewprofile",
        "btcpay.user.canmanageprofile"
    ]
}

data_bytes = json.dumps(data).encode('utf-8')

endpoints = ["/api/v1/api-keys", f"/api/v1/users/{EMAIL}/api-keys"]
success = False

for ep in endpoints:
    req = urllib.request.Request(f"{URL}{ep}", data=data_bytes, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req) as response:
            status = response.getcode()
            body = response.read().decode('utf-8')
            if status in [200, 201]:
                res_json = json.loads(body)
                key = res_json.get('apiKey')
                print(f"Generated API Key: {key}")
                with open("fuzzer.env", "w") as f:
                    f.write(f"AUTH_HEADER=Authorization: token {key}\n")
                print(f"Saved to fuzzer.env: token {key}")
                success = True
                break
    except urllib.error.HTTPError as e:
        print(f"Endpoint {ep} failed: {e.code}")
        body = e.read().decode('utf-8')
        print(f"Response: {body}")
    except Exception as e:
        print(f"Endpoint {ep} failed: {e}")

if not success:
    print("Failed to generate API Key on all endpoints.")
    exit(1)
