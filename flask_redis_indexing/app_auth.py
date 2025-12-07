#!/usr/bin/env python3
import time
import secrets
import hashlib
import hmac

from flask import Flask, request, make_response

from common import r, log_attempt

# -------------------- Настройки --------------------

# лимиты
MAX_ATTEMPTS  = 5           # сколько неудачных попыток до блокировки
BLOCK_SECONDS = 60          # на сколько секунд блокировать (сек)
BASE_SLEEP    = 0.2         # минимальная задержка на любой ответ (сек)
TOKEN_TTL     = 600         # время жизни токена в Redis (сек)

app = Flask(__name__)


# -------------------- Хеширование пароля --------------------


def hash_password(password: str, salt: bytes | None = None) -> str:
    """
    Стойкое хеширование пароля через PBKDF2-HMAC-SHA256.
    Возвращаем строку вида: salt_hex$hash_hex
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 150_000)
    return f"{salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """
    Проверяем пароль против строки salt$hash.
    """
    try:
        salt_hex, hash_hex = stored.split("$", 1)
    except ValueError:
        return False
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 150_000)
    return hmac.compare_digest(dk.hex(), hash_hex)


# -------------------- Инициализация пользователя --------------------


def ensure_admin_user():
    """
    Создаём пользователя admin с паролем ab21, если его ещё нет в Redis.
    Для реального приложения так делать нельзя, но для лабы нормально.
    """
    key = "auth:user:admin:password"
    if not r.exists(key):
        r.set(key, hash_password("ab21"))
        # сюда же можно добавить роли, e-mail и т.п. в другие ключи


ensure_admin_user()


# -------------------- Вспомогательные функции (идентификация клиента) --------------------


def client_id() -> str:
    """
    Простейший идентификатор клиента: IP + User-Agent.
    Этого достаточно для лабы, чтобы ограничить брут с одного места.
    """
    ip = request.remote_addr or "unknown"
    ua = request.headers.get("User-Agent", "unknown")
    return f"{ip}|{ua}"


def is_blocked(username: str) -> bool:
    cid = client_id()
    block_key = f"auth:block:{cid}:{username}"
    return r.exists(block_key)


def register_failure(username: str) -> None:
    cid = client_id()
    fail_key = f"auth:fail:{cid}:{username}"
    block_key = f"auth:block:{cid}:{username}"

    fails = r.incr(fail_key)
    # счётчик живёт 5 минут
    r.expire(fail_key, 300)

    if fails >= MAX_ATTEMPTS:
        # ставим блокировку
        r.set(block_key, b"1", ex=BLOCK_SECONDS)


def reset_failures(username: str) -> None:
    cid = client_id()
    fail_key = f"auth:fail:{cid}:{username}"
    block_key = f"auth:block:{cid}:{username}"
    r.delete(fail_key)
    r.delete(block_key)


# -------------------- Токен (по-взрослому) --------------------


def token_key() -> str:
    """
    Ключ для хранения токена в Redis для конкретного клиента.
    Привязан к client_id() (IP + User-Agent).
    """
    return f"auth:token:{client_id()}"


def issue_token() -> str:
    """
    Генерирует новый случайный токен, кладёт его в Redis с TTL и возвращает.
    """
    token = secrets.token_hex(16)  # 32-символьная hex-строка
    r.set(token_key(), token, ex=TOKEN_TTL)
    return token


def get_stored_token() -> str | None:
    """
    Достаёт токен из Redis. Если нет – возвращает None.
    """
    raw = r.get(token_key())
    if not raw:
        return None
    return raw.decode("utf-8")


def clear_token() -> None:
    """
    Удаляет токен из Redis (можно вызывать после успешного логина).
    """
    r.delete(token_key())


# -------------------- Маршрут аутентификации --------------------


@app.route("/vulnerabilities/brute/", methods=["GET"])
def authenticate():
    """
    Безопасная версия DVWA Brute Force.
    Принимает те же GET-параметры:
      ?username=USER&password=PASS&user_token=TOKEN&Login=1
    Но:
      * проверяет лимиты попыток
      * хранит пароль в стойком виде
      * использует случайный токен, привязанный к клиенту
    """
    time.sleep(BASE_SLEEP)  # чуть замедляем любой ответ

    username   = request.args.get("username", "")
    password   = request.args.get("password", "")
    user_token = request.args.get("user_token")
    login_flag = request.args.get("Login")

    source = "safe_auth"

    # --- 1. Нет Login=1 → просто отдаём форму + токен ---
    if login_flag is None:
        # берём токен из Redis или создаём новый
        token = get_stored_token()
        if token is None:
            token = issue_token()

        html = f"""
        <html>
        <body>
          <h3>Safe Auth (protected brute-force)</h3>
          <form method="get" action="/vulnerabilities/brute/">
            <label>Username:
              <input type="text" name="username" value="{username}">
            </label><br/>
            <label>Password:
              <input type="password" name="password">
            </label><br/>
            <input type="hidden" name="user_token" value="{token}">
            <button type="submit" name="Login" value="1">Login</button>
          </form>
        </body>
        </html>
        """
        # это не попытка логина, можно не логировать
        return make_response(html, 200)

    # --- 2. Есть Login=1 → должен быть корректный токен ---
    stored_token = get_stored_token()
    if not stored_token or not user_token or not hmac.compare_digest(user_token, stored_token):
        # Токен отсутствует или не совпадает — считаем попытку неуспешной
        log_attempt(username, password, False, source)
        resp = make_response("<pre>Invalid or missing user_token.</pre>", 400)
        return resp

    # --- 3. Проверка блокировки по лимиту ---
    if is_blocked(username):
        log_attempt(username, password, False, source)
        resp = make_response(
            "<pre>Too many failed attempts. Try again later.</pre>", 429
        )
        return resp

    # --- 4. Достаём хеш пароля пользователя ---
    pw_key = f"auth:user:{username}:password"
    stored_hash = r.get(pw_key)
    if not stored_hash:
        # Пользователь не найден — имитируем задержку и регистрируем неудачу
        time.sleep(0.3)
        register_failure(username)
        log_attempt(username, password, False, source)
        html = "<pre><br />Username and/or password incorrect.</pre>"
        return make_response(html, 401)

    stored_hash = stored_hash.decode("utf-8")

    if not verify_password(password, stored_hash):
        # Неверный пароль
        register_failure(username)
        log_attempt(username, password, False, source)
        html = "<pre><br />Username and/or password incorrect.</pre>"
        return make_response(html, 401)

    # --- 5. Успешный логин ---
    reset_failures(username)
    clear_token()  # опционально очищаем токен (один логин — один токен)

    log_attempt(username, password, True, source)
    html = f"<p>Welcome to the password protected area {username}</p>"
    return make_response(html, 200)


if __name__ == "__main__":
    # В лабы удобно оставить debug=True
    app.run(host="0.0.0.0", port=8081, debug=True)

