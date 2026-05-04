"""
encrypt_token.py — Шифрование токенов и ключей бота
=====================================================
Использование:
  1. Первый запуск:  python3 encrypt_token.py
     → вводишь мастер-пароль и все токены → сохраняется encrypted_config.json

  2. Проверка:       python3 encrypt_token.py --show
     → вводишь мастер-пароль → видишь расшифрованные значения

Зависимости: pip install cryptography
"""

import os
import json
import base64
import getpass
import argparse
import sys

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.fernet import Fernet
except ImportError:
    print("❌ Установите библиотеку: pip install cryptography")
    sys.exit(1)

ENCRYPTED_FILE = "encrypted_config.json"
ITERATIONS = 480_000  # PBKDF2 итерации (чем больше — тем медленнее брутфорс)


def derive_key(password: str, salt: bytes) -> bytes:
    """Выводит ключ шифрования из пароля через PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_all(values: dict, password: str) -> dict:
    """Шифрует словарь значений. Каждое значение — отдельный Fernet-токен."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)

    encrypted = {}
    for name, value in values.items():
        encrypted[name] = f.encrypt(value.encode()).decode()

    return {
        "salt": base64.b64encode(salt).decode(),
        "iterations": ITERATIONS,
        "data": encrypted,
    }


def decrypt_all(payload: dict, password: str) -> dict:
    """Расшифровывает все значения из зашифрованного файла."""
    salt = base64.b64decode(payload["salt"])
    key = derive_key(password, salt)
    f = Fernet(key)

    result = {}
    for name, encrypted_value in payload["data"].items():
        result[name] = f.decrypt(encrypted_value.encode()).decode()
    return result


def load_encrypted_config() -> dict:
    if not os.path.exists(ENCRYPTED_FILE):
        print(f"❌ Файл {ENCRYPTED_FILE} не найден. Сначала запустите без флагов.")
        sys.exit(1)
    with open(ENCRYPTED_FILE, "r") as f:
        return json.load(f)


def cmd_encrypt():
    """Интерактивный ввод токенов и шифрование."""
    print("=" * 50)
    print("  🔐 Шифрование конфигурации бота")
    print("=" * 50)
    print()

    if os.path.exists(ENCRYPTED_FILE):
        answer = input(f"⚠️  Файл {ENCRYPTED_FILE} уже существует. Перезаписать? (да/нет): ").strip().lower()
        if answer not in ("да", "д", "yes", "y"):
            print("Отменено.")
            sys.exit(0)
        print()

    # Ввод мастер-пароля
    while True:
        password = getpass.getpass("🔑 Придумайте мастер-пароль: ")
        if len(password) < 8:
            print("   ❌ Пароль должен быть не короче 8 символов.")
            continue
        confirm = getpass.getpass("🔑 Повторите мастер-пароль: ")
        if password != confirm:
            print("   ❌ Пароли не совпадают. Попробуйте снова.\n")
            continue
        break

    print()
    print("Введите значения (Enter — пропустить необязательные):")
    print()

    fields = [
        ("TELEGRAM_BOT_TOKEN",  "Telegram Bot Token",          True),
        ("GROQ_API_KEY",         "Groq API Key",                True),
        ("ADMIN_PASSWORD",       "Пароль администратора",       True),
        ("POLLINATIONS_API_KEY", "Pollinations API Key",        False),
        ("CLOUD_CHANNEL_ID",     "ID облачного канала (число)", False),
    ]

    values = {}
    for key, label, required in fields:
        while True:
            value = input(f"  {label}: ").strip()
            if not value:
                if required:
                    print(f"   ❌ Это поле обязательно.")
                    continue
                else:
                    break
            values[key] = value
            break

    print()
    print("⏳ Шифрую... (это займёт пару секунд)")

    payload = encrypt_all(values, password)

    with open(ENCRYPTED_FILE, "w") as f:
        json.dump(payload, f, indent=2)

    print(f"✅ Готово! Сохранено в {ENCRYPTED_FILE}")
    print()
    print("📋 Что дальше:")
    print(f"   1. Добавьте {ENCRYPTED_FILE} в репозиторий (он безопасен без мастер-пароля)")
    print(f"   2. Добавьте config.py в .gitignore (или удалите его)")
    print(f"   3. При запуске бота введите мастер-пароль")
    print()
    print("⚠️  НЕ ЗАБУДЬТЕ мастер-пароль — восстановить его невозможно!")


def cmd_show():
    """Показывает расшифрованные значения."""
    print("=" * 50)
    print("  🔓 Просмотр конфигурации")
    print("=" * 50)
    print()

    payload = load_encrypted_config()
    password = getpass.getpass("🔑 Мастер-пароль: ")

    try:
        values = decrypt_all(payload, password)
    except Exception:
        print("❌ Неверный пароль.")
        sys.exit(1)

    print()
    print("Расшифрованные значения:")
    for key, value in values.items():
        # Маскируем середину для безопасности при демонстрации
        if len(value) > 8:
            masked = value[:4] + "*" * (len(value) - 8) + value[-4:]
        else:
            masked = "****"
        print(f"  {key}: {masked}")
    print()
    print("✅ Пароль верный, данные корректны.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Шифрование конфигурации Telegram-бота")
    parser.add_argument("--show", action="store_true", help="Показать расшифрованные значения")
    args = parser.parse_args()

    if args.show:
        cmd_show()
    else:
        cmd_encrypt()
