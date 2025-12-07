#!/usr/bin/env python3
import os
import time
import json
import redis
import pymysql

STORAGE_MODE = os.getenv("STORAGE_MODE", "redis").lower()

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB   = int(os.getenv("REDIS_DB", "0"))

r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    decode_responses=True,
)


def get_sql_connection():
    """Создаём новое подключение к MariaDB (используем только в STORAGE_MODE=sql)."""
    host = os.getenv("SQL_HOST", "labdb")
    port = int(os.getenv("SQL_PORT", "3306"))
    user = os.getenv("SQL_USER", "labuser")
    password = os.getenv("SQL_PASSWORD", "labpass")
    db = os.getenv("SQL_DB", "bruteforce")

    return pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=db,
        autocommit=True,
    )


def log_attempt(username: str,
                password: str,
                success: bool,
                source: str = "external_script",
                ip: str | None = None):
    """
    Универсальное логирование:
    - всегда пишет в Redis (для совместимости с текущим мониторингом);
    - в режиме STORAGE_MODE=sql дополнительно пишет в таблицу auth_attempts MariaDB.
    """
    item = {
        "ts": time.time(),
        "username": username,
        "password": password,
        "success": bool(success),
        "source": source,
        "ip": ip or "unknown",
    }

    r.rpush("bruteforce_attempts", json.dumps(item))

    if STORAGE_MODE == "sql":
        try:
            conn = get_sql_connection()
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO auth_attempts
                        (source, username, ip_address, password_candidate, success)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (source, username, item["ip"], password, bool(success)),
                )
            conn.close()
        except Exception as e:
            print(f"[WARN] Failed to log to SQL: {e}", flush=True)

    return item

