import token
from fastapi import FastAPI, Header, HTTPException, Cookie, Response
from pydantic import BaseModel
import secrets
import redis
import json
import hashlib
from datetime import datetime, timedelta, timezone
import jwt
from pathlib import Path
from jwt import InvalidTokenError


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

REFRESH_TOKEN_TTL = 7 * 24 * 60 * 60

# =====================================================
# LAB 6: JWT AUTHENTICATION - RS256
# =====================================================

KEYS_DIR = Path("/app/keys")

ROTATE_REFRESH_SCRIPT = """
-- KEYS[1]: old refresh token key
-- KEYS[2]: new refresh token key
-- KEYS[3]: family index key
-- KEYS[4]: family revocation key

-- ARGV[1]: refresh token maximum lifetime (seconds)

local old_raw = redis.call("GET", KEYS[1])

if not old_raw then
    return 0
end

local old_data = cjson.decode(old_raw)

-- Validate family keys BEFORE any writes
local expected_family_key =
    "family:" .. old_data.family_id .. ":tokens"

local expected_revoked_key =
    "family:" .. old_data.family_id .. ":revoked"

if KEYS[3] ~= expected_family_key
    or KEYS[4] ~= expected_revoked_key then
    return redis.error_reply("Family key mismatch")
end

-- 1. Family already revoked
if redis.call("EXISTS", KEYS[4]) == 1 then
    return 0
end

-- 2. Detect refresh token reuse
if old_data.status == "used" then

    redis.call(
        "SET",
        KEYS[4],
        "1",
        "EX",
        tonumber(ARGV[1])
    )

    return -1
end

-- 3. Only active tokens can rotate
if old_data.status ~= "active" then
    return 0
end

-- 4. Check remaining TTL
local ttl = redis.call("TTL", KEYS[1])

if ttl <= 0 then
    return 0
end

-- 5. Prevent accidental overwrite
if redis.call("EXISTS", KEYS[2]) == 1 then
    return 0
end

-- 6. Create new refresh token metadata
local new_data = {
    username = old_data.username,
    family_id = old_data.family_id,
    status = "active"
}

-- 7. Mark old token as used
old_data.status = "used"

redis.call(
    "SET",
    KEYS[1],
    cjson.encode(old_data),
    "KEEPTTL"
)

-- 8. Save new refresh token
redis.call(
    "SET",
    KEYS[2],
    cjson.encode(new_data),
    "EX",
    ttl
)

-- 9. Update family index
redis.call(
    "SADD",
    KEYS[3],
    KEYS[1],
    KEYS[2]
)

redis.call("EXPIRE", KEYS[3], ttl)

-- 10. Return rotation result
return cjson.encode({
    username = old_data.username,
    family_id = old_data.family_id
})
"""
private_key_path = KEYS_DIR / "private.pem"

PRIVATE_KEY = (
    private_key_path.read_text()
    if private_key_path.exists()
    else None
)

PUBLIC_KEY = (KEYS_DIR / "public.pem").read_text()
JWT_ALGORITHM = "RS256"
JWT_ISSUER = "api-auth-lab"
JWT_AUDIENCE = "orders-api"
JWT_EXPIRE_MINUTES = 1


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


@app.post("/jwt/login")
def jwt_login(data: LoginRequest):

    # 1. Authenticate user
    user = USERS.get(data.username)

    if user is None or user["password"] != data.password:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    # 2. Prepare JWT claims
    now = datetime.now(timezone.utc)

    payload = {
        "sub": data.username,
        "role": user["role"],
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + timedelta(minutes=1)
    }
    
    if PRIVATE_KEY is None:
        raise HTTPException(
        status_code=403,
        detail="This service cannot issue JWT"
    )

    # 3. Sign JWT using RSA Private Key
    access_token = jwt.encode(
        payload,
        PRIVATE_KEY,
        algorithm=JWT_ALGORITHM
    )

    refresh_token = create_refresh_token(data.username)

    # 4. Return token
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token,
        "expires_in": JWT_EXPIRE_MINUTES * 60
    }


@app.get("/jwt/orders")
def get_jwt_orders(
    authorization: str | None = Header(default=None)
):

    # 1. Check Authorization header
    if authorization is None:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header"
        )

    scheme, separator, token = authorization.partition(" ")

    if scheme.lower() != "bearer" or not separator or not token:
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization scheme"
        )

    # 2. Verify JWT using Public Key
    try:
        payload = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={
                "require": ["sub", "exp", "iat", "iss", "aud"]
            }
        )

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="JWT expired"
        )

    except InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid JWT"
        )

    # 3. Authorization
    if payload.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Permission denied"
        )

    # 4. Return orders
    return {
        "username": payload["sub"],
        "role": payload["role"],
        "orders": orders
    }



def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

def generate_refresh_token():
    token = secrets.token_urlsafe(32)
    token_hash = hash_refresh_token(token)

    return token, token_hash

def create_refresh_token(username: str) -> str:
    # Tạo Refresh Token ngẫu nhiên
    refresh_token = secrets.token_urlsafe(32)

    # Tạo ID cho một chuỗi Refresh Token
    family_id = secrets.token_urlsafe(16)

    # Hash token trước khi lưu Redis
    token_hash = hash_refresh_token(refresh_token)

    # Metadata
    token_data = {
        "username": username,
        "family_id": family_id,
        "status": "active"
    }

    # 5. Tạo tên các Redis key
    refresh_key = f"refresh:{token_hash}"
    family_key = f"family:{family_id}:tokens"

    # 6. Lưu Refresh Token và Family Index
    with redis_client.pipeline(transaction=True) as pipe:
        pipe.setex(
            refresh_key,
            REFRESH_TOKEN_TTL,
            json.dumps(token_data)
        )

        pipe.sadd(family_key, refresh_key)

        pipe.expire(family_key, REFRESH_TOKEN_TTL)

        pipe.execute()

    return refresh_token

class RefreshRequest(BaseModel):
    refresh_token: str


@app.post("/jwt/refresh")
def jwt_refresh(data: RefreshRequest):

    # 1. Rotate Refresh Token
    result = rotate_refresh_token(data.refresh_token)

    # 2. Detect reuse
    if result["status"] == "reuse_detected":
        raise HTTPException(
            status_code=401,
            detail="Refresh token reuse detected. Please login again."
        )

    # 3. Reject invalid or revoked tokens
    if result["status"] != "success":
        raise HTTPException(
            status_code=401,
            detail="Invalid or revoked refresh token"
        )

    # 4. Get user
    username = result["username"]
    user = USERS.get(username)

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    # 5. Create new Access Token (RS256)
    now = datetime.now(timezone.utc)

    payload = {
        "sub": username,
        "role": user["role"],
        "iss": "api-auth-lab",
        "aud": "orders-api",
        "iat": now,
        "exp": now + timedelta(minutes=1)
    }

    access_token = jwt.encode(
        payload,
        PRIVATE_KEY,
        algorithm="RS256"
    )

    # 6. Return new token pair
    return {
        "access_token": access_token,
        "refresh_token": result["refresh_token"],
        "token_type": "bearer",
        "expires_in": 60
    }

def rotate_refresh_token(old_token: str):
    old_hash = hash_refresh_token(old_token)
    old_key = f"refresh:{old_hash}"

    # Read metadata to determine family ID
    old_raw = redis_client.get(old_key)

    if old_raw is None:
        return {
            "status": "invalid"
        }

    old_data = json.loads(old_raw)

    family_id = old_data["family_id"]

    # Generate replacement token
    new_token, new_hash = generate_refresh_token()

    new_key = f"refresh:{new_hash}"

    family_key = f"family:{family_id}:tokens"
    revoked_key = f"family:{family_id}:revoked"

    # Execute atomically
    result = redis_client.eval(
        ROTATE_REFRESH_SCRIPT,
        4,
        old_key,
        new_key,
        family_key,
        revoked_key,
        REFRESH_TOKEN_TTL
    )

    if result == -1:
        return {
            "status": "reuse_detected"
        }

    if result == 0:
        return {
            "status": "invalid"
        }

    token_data = json.loads(result)

    return {
        "status": "success",
        "refresh_token": new_token,
        "username": token_data["username"],
        "family_id": token_data["family_id"]
    }