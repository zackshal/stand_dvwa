import os
import time
import json
import redis

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB   = int(os.getenv("REDIS_DB", "0"))

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)


def log_attempt(username: str, password: str, success: bool, source: str = "external_script"):
    item = {
        "ts": time.time(),
        "username": username,
        "password": password,
        "success": bool(success),
        "source": source,
    }
    r.rpush("bruteforce_attempts", json.dumps(item))
    return item

