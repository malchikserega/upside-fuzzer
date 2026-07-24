import requests
import re

session = requests.Session()
response = session.get("http://localhost:7777/login")
match = re.search(r'name="__RequestVerificationToken" type="hidden" value="([^"]+)"', response.text)
if not match:
    print("Failed to find antiforgery token")
    exit(1)

token = match.group(1)

data = {
    '__RequestVerificationToken': token,
    'Email': 'admin@simplcommerce.com',
    'Password': '1qazZAQ!',
    'RememberMe': 'false'
}
resp2 = session.post("http://localhost:7777/login", data=data, allow_redirects=False)
cookies = []
for cookie in session.cookies:
    cookies.append(f"{cookie.name}={cookie.value}")

if cookies:
    cookie_str = "; ".join(cookies)
    with open("fuzzer.env", "w") as f:
        f.write(f"AUTH_COOKIE={cookie_str}\n")
    print("Wrote AUTH_COOKIE to fuzzer.env")
else:
    print("Failed to get cookies!")
