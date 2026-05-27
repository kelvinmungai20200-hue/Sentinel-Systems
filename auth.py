from jose import jwt, JWTError
from datetime import datetime, timedelta

SECRET = "sentinel_enterprise_neural_secure_key_2026"
ALGO = "HS256"

def create_token(data: dict):
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(days=7) 
    return jwt.encode(payload, SECRET, algorithm=ALGO)

def verify_token(token: str):
    try:
        return jwt.decode(token, SECRET, algorithms=[ALGO])
    except JWTError:
        return None
