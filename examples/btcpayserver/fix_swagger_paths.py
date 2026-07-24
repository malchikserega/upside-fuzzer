import json

path = "btcpayserver_prep/swagger-btc.json"
with open(path, "r") as f:
    content = f.read()

# Replace the reference string
content = content.replace("#/components/parameters/Subscriptions/Currency", "#/components/parameters/Subscriptions_Currency")

data = json.loads(content)

if "Subscriptions/Currency" in data.get("components", {}).get("parameters", {}):
    data["components"]["parameters"]["Subscriptions_Currency"] = data["components"]["parameters"].pop("Subscriptions/Currency")

with open(path, "w") as f:
    json.dump(data, f, indent=2)
