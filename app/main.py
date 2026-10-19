from fastapi import FastAPI, Header, HTTPException, Cookie, Response
from pydantic import BaseModel
import secrets
import redis
import json
from datetime import datetime, timedelta, timezone
app = FastAPI(
    title="API Authentication Lab",
    description="Practice API Key, Authorization and Session Authentication",
    version="1.0.0"
)

redis_client = redis.Redis(
    host="redis",
    port=6379,
    db=0,
    decode_responses=True
)



# =====================================================
# LAB 1: API KEY AUTHENTICATION
# =====================================================

API_KEYS = {
    "report-secret-123": {
        "client": "daily_report",
        "permissions": ["orders:read"],
        "active": True
    },
    "admin-secret-456": {
        "client": "order_admin",
        "permissions": ["orders:read", "orders:delete"],
        "active": True
    }
}

orders = [
    {"order_id": 1, "customer": "Vy", "product": "iPhone"},
    {"order_id": 2, "customer": "An", "product": "MacBook"},
    {"order_id": 3, "customer": "Nam", "product": "Keyboard"},
]


def authenticate_api_key(x_api_key: str | None):
    client = API_KEYS.get(x_api_key)

    if client is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid API Key"
        )

    if not client["active"]:
        raise HTTPException(
            status_code=401,
            detail="API Key revoked"
        )

    return client


@app.get("/")
def home():
    return {"message": "API Authentication Lab is running"}


@app.get("/orders")
def get_orders(x_api_key: str | None = Header(default=None)):
    client = authenticate_api_key(x_api_key)

    if "orders:read" not in client["permissions"]:
        raise HTTPException(
            status_code=403,
            detail="Permission denied"
        )

    return {
        "client": client["client"],
        "orders": orders
    }


# =====================================================
# LAB 2: AUTHORIZATION / PERMISSIONS
# =====================================================

@app.delete("/orders/{order_id}")
def delete_order(
    order_id: int,
    x_api_key: str | None = Header(default=None)
):
    client = authenticate_api_key(x_api_key)

    if "orders:delete" not in client["permissions"]:
        raise HTTPException(
            status_code=403,
            detail="Permission denied"
        )

    for order in orders:
        if order["order_id"] == order_id:
            orders.remove(order)

            return {
                "message": "Order deleted successfully",
                "deleted_order_id": order_id,
                "deleted_by": client["client"]
            }

    raise HTTPException(
        status_code=404,
        detail="Order not found"
    )


# =====================================================
# LAB 3: SESSION AUTHENTICATION (IN-MEMORY)
# =====================================================

USERS = {
    "vy": {
        "password": "123456",
        "role": "admin"
    }
}

SESSIONS = {}


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(data: LoginRequest, response: Response):
    user = USERS.get(data.username)

    if user is None or user["password"] != data.password:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )
    session_id = secrets.token_urlsafe(32)
    session_data = {
        "username": data.username,
        "role": user["role"]
    }

    try:
        redis_client.setex(
            name=f"session:{session_id}",
            time=1800,
            value=json.dumps(session_data)
        )
    except redis.RedisError:
        raise HTTPException(
            status_code=503,
            detail="Session store unavailable"
        )

    # 4. Trả Session ID về client thông qua Cookie
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        samesite="lax",
        max_age=1800
    )

    return {"message": "Login successful"}

@app.get("/session/orders")
def get_session_orders(
    session_id: str | None = Cookie(default=None)
):
    # 1. Kiểm tra client có gửi Session ID không
    if session_id is None:
        raise HTTPException(
            status_code=401,
            detail="Missing session"
        )

    # 2. Đọc Session từ Redis
    try:
        session_json = redis_client.get(
            f"session:{session_id}"
        )
    except redis.RedisError:
        raise HTTPException(
            status_code=503,
            detail="Session store unavailable"
        )

    # 3. Kiểm tra Session còn tồn tại không
    if session_json is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired session"
        )

    # 4. Chuyển JSON string thành Python dictionary
    session = json.loads(session_json)

    # 5. Trả dữ liệu cho user
    return {
        "username": session["username"],
        "orders": orders
    }


# =====================================================
# LAB 4: LOGOUT / SESSION REVOCATION
# =====================================================

@app.post("/logout")
def logout(
    response: Response,
    session_id: str | None = Cookie(default=None)
):
    # 1. Nếu client có gửi Session ID
    if session_id is not None:
        try:
            # 2. Xóa Session trong Redis
            redis_client.delete(f"session:{session_id}")
        except redis.RedisError:
            raise HTTPException(
                status_code=503,
                detail="Session store unavailable"
            )

    # 3. Yêu cầu trình duyệt xóa Cookie
    response.delete_cookie(key="session_id")

    return {"message": "Logout successful"}


# =====================================================
# DEBUG ONLY
# =====================================================

@app.get("/debug/sessions")
def debug_sessions():
    return {
        "total_sessions": len(SESSIONS),
        "sessions": SESSIONS
    }


@app.get("/redis/ping")
def redis_ping():
    try:
        result = redis_client.ping()
        return {"redis_connected": result}
    except redis.RedisError:
        raise HTTPException(
            status_code=503,
            detail="Redis is unavailable"
        )


TOKENS = {}

@app.post("/token/login")
def token_login(data: LoginRequest):
    user = USERS.get(data.username)

    if user is None or user["password"] != data.password:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    access_token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=30)

    TOKENS[access_token] = {
        "username": data.username,
        "role": user["role"],
        "expires_at": expires_at
    }

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_at": 30
    }


@app.get("/token/orders")
def get_token_orders(
    authorization: str | None = Header(default=None)
):
    if authorization is None:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header"
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization scheme"
        )

    access_token = authorization.removeprefix("Bearer ")

    user = TOKENS.get(access_token)

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid access token"
        )

    # Phải kiểm tra hết hạn TRƯỚC khi trả dữ liệu
    if datetime.now(timezone.utc) >= user["expires_at"]:
        TOKENS.pop(access_token, None)

        raise HTTPException(
            status_code=401,
            detail="Access token expired"
        )

    return {
        "username": user["username"],
        "role": user["role"],
        "orders": orders
    }
