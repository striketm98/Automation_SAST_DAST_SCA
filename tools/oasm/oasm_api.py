from flask import Flask, jsonify


app = Flask(__name__)


ASSETS = [
    {
        "asset_type": "domain",
        "asset_name": "client.example.com",
        "asset_url": "https://client.example.com",
        "exposure": "public",
        "status": "reviewed",
        "notes": "Primary portal under ongoing monitoring.",
    },
    {
        "asset_type": "api",
        "asset_name": "api.client.example.com",
        "asset_url": "https://api.client.example.com",
        "exposure": "public",
        "status": "discovered",
        "notes": "API surface queued for validation.",
    },
    {
        "asset_type": "subdomain",
        "asset_name": "dev.client.example.com",
        "asset_url": "https://dev.client.example.com",
        "exposure": "internal",
        "status": "in_scope",
        "notes": "Internal environment tracked for exposure control.",
    },
]


@app.get("/health")
def health():
    return jsonify(status="ok", service="oasm")


@app.get("/assets")
def assets():
    return jsonify(service="Open Attack Surface Management", assets=ASSETS)


@app.get("/summary")
def summary():
    return jsonify(
        service="Open Attack Surface Management",
        total_assets=len(ASSETS),
        public_assets=len([item for item in ASSETS if item["exposure"] == "public"]),
        reviewed_assets=len([item for item in ASSETS if item["status"] == "reviewed"]),
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=6200)
