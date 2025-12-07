import json

from flask import Flask, jsonify, request, render_template

from common import r, log_attempt

app = Flask(__name__)


@app.route("/")
def index():
    visits = r.incr("visits")
    return jsonify(
        message="Hello from Flask + Redis",
        visits=visits
    )


@app.route("/attempts", methods=["POST"])
def add_attempt():
    """
    Принимаем JSON вида:
    {
      "username": "admin",
      "password": "ab21",
      "success": true,
      "source": "dvwa_bruteforce"
    }
    и пишем в Redis через общий log_attempt.
    """
    data = request.get_json(silent=True) or {}

    username = data.get("username", "unknown")
    password = data.get("password", "")
    success  = bool(data.get("success", False))
    source   = data.get("source", "external_script")

    stored = log_attempt(username, password, success, source)
    return jsonify(status="ok", stored=stored)


@app.route("/attempts", methods=["GET"])
def list_attempts():
    """
    ?limit=10 — вернуть последние 10 попыток, по умолчанию 50.
    """
    limit = int(request.args.get("limit", 50))

    length = r.llen("bruteforce_attempts")
    start = max(0, length - limit)
    end = length - 1

    raw_items = r.lrange("bruteforce_attempts", start, end)
    attempts = [json.loads(x) for x in raw_items]

    return jsonify(count=len(attempts), attempts=attempts)


@app.route("/stats", methods=["GET"])
def stats():
    raw = r.lrange("bruteforce_attempts", 0, -1)
    attempts = [json.loads(x) for x in raw]

    total = len(attempts)
    success = sum(1 for a in attempts if a["success"])
    fail = total - success
    users = list(sorted(set(a["username"] for a in attempts)))

    return jsonify(
        total=total,
        success=success,
        fail=fail,
        users=users
    )


@app.route("/success-rate", methods=["GET"])
def success_rate():
    raw = r.lrange("bruteforce_attempts", 0, -1)
    attempts = [json.loads(x) for x in raw]

    if not attempts:
        return jsonify(rate=0)

    success = sum(1 for a in attempts if a["success"])
    return jsonify(rate=round(success / len(attempts) * 100, 2))


@app.route("/by-user/<username>", methods=["GET"])
def by_user(username):
    raw = r.lrange("bruteforce_attempts", 0, -1)
    attempts = [json.loads(x) for x in raw if x]

    user_attempts = [a for a in attempts if a["username"] == username]

    return jsonify(
        username=username,
        count=len(user_attempts),
        attempts=user_attempts[-50:]  # последние 50
    )


@app.route("/monitor")
def monitor():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

