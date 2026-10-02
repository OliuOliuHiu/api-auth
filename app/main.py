from fastapi import FastAPI, Header, HTTPException

app = FastAPI()

API_KEYS = {
    "report-secret-123": {
        "client": "daily_report",
        "permissions": ["orders:read"]
    },
    "admin-secret-456": {
        "client": "order_admin",
        "permissions": [
            "orders:read",
            "orders:delete"
        ]
    }
}

orders = [
    {"order_id": 1, "customer": "Vy", "product": "iPhone"},
    {"order_id": 2, "customer": "An", "product": "MacBook"},
    {"order_id": 3, "customer": "Nam", "product": "Keyboard"},
]


@app.get("/orders")
def get_orders(x_api_key: str | None = Header(default=None)):

    if x_api_key not in API_KEYS:
        raise HTTPException(
            status_code=401,
            detail="Invalid API Key"
        )

    return orders
