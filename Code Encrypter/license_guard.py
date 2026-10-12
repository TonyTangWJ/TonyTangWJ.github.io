"""Runtime license verification copied beside an encrypted application."""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import subprocess
import sys
from ctypes import wintypes
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from tkinter import TclError, Tk, messagebox

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.ui import WebDriverWait


DEFAULT_OWNER_EMAIL = "wenjun.a.tang@accenture.cn"
CACHE_PATH = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "Python Code Encrypter" / "authorization-cache.bin"


class DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def show_progress(step: str) -> None:
    print(f"[Authorization] {step}", flush=True)


def device_hash(device_code: str) -> str:
    return hashlib.sha256(device_code.strip().encode("utf-8")).hexdigest()


def protect_cache(data: bytes) -> bytes:
    buffer = ctypes.create_string_buffer(data)
    input_blob = DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
    output_blob = DataBlob()
    if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(input_blob), None, None, None, None, 0, ctypes.byref(output_blob)):
        raise OSError(ctypes.get_last_error(), "Windows DPAPI could not encrypt the authorization cache.")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(output_blob.pbData)


def unprotect_cache(data: bytes) -> bytes:
    buffer = ctypes.create_string_buffer(data)
    input_blob = DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
    output_blob = DataBlob()
    if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(input_blob), None, None, None, None, 0, ctypes.byref(output_blob)):
        raise OSError(ctypes.get_last_error(), "Windows DPAPI could not read the authorization cache.")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(output_blob.pbData)


def public_key_fingerprint(public_key_pem: str) -> str:
    return hashlib.sha256(public_key_pem.encode("utf-8")).hexdigest()


def cache_is_valid(public_key_pem: str, device_code: str) -> bool:
    try:
        payload = json.loads(unprotect_cache(CACHE_PATH.read_bytes()).decode("utf-8"))
        cache_until = datetime.fromisoformat(payload["cache_until"])
        return (
            cache_until > datetime.now(timezone.utc)
            and payload["device_hash"] == device_hash(device_code)
            and payload["public_key_fingerprint"] == public_key_fingerprint(public_key_pem)
        )
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def write_authorization_cache(public_key_pem: str, device_code: str, expires_on: str) -> None:
    license_until = datetime.combine(date.fromisoformat(expires_on) + timedelta(days=1), time.min, timezone.utc)
    cache_until = min(datetime.now(timezone.utc) + timedelta(days=5), license_until)
    payload = {
        "device_hash": device_hash(device_code),
        "public_key_fingerprint": public_key_fingerprint(public_key_pem),
        "cache_until": cache_until.isoformat(),
    }
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = CACHE_PATH.with_suffix(".tmp")
    temporary_path.write_bytes(protect_cache(json.dumps(payload, sort_keys=True).encode("utf-8")))
    temporary_path.replace(CACHE_PATH)


def get_device_code() -> str:
    """Read the local Windows hardware UUID used for device-bound authorization."""
    show_progress("1/4 Reading this computer's hardware UUID...")
    result = subprocess.run(
        [
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            "(Get-CimInstance Win32_ComputerSystemProduct).UUID",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        details = result.stderr.strip() or "PowerShell could not read the device UUID."
        raise RuntimeError(details)
    device_code = result.stdout.strip()
    if not device_code:
        raise RuntimeError("PowerShell returned an empty device UUID.")
    show_progress("1/4 Hardware UUID read.")
    return device_code


def crawl_authorizations(page_url: str) -> tuple[str, list[dict[str, str]]]:
    """Load the rendered page and extract authorization objects created from YAML."""
    show_progress("2/4 Loading the authorization page...")
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    driver = webdriver.Chrome(options=options)
    try:
        driver.get(page_url)
        wait = WebDriverWait(driver, 15)
        footer_email = wait.until(expected_conditions.presence_of_element_located(
            (By.CSS_SELECTOR, 'footer [data-encryption="planned"]')
        )).text.strip()
        elements = wait.until(expected_conditions.presence_of_all_elements_located((By.CSS_SELECTOR, ".authorization")))
        users = [{
            "name": element.get_attribute("data-name") or "",
            "signature": element.get_attribute("data-signature") or "",
            "license": element.get_attribute("data-license") or "",
            "deviceHash": element.text.removeprefix("DeviceHash:").strip(),
        } for element in elements]
        show_progress("2/4 Authorization page loaded.")
        return footer_email, users
    finally:
        driver.quit()


def verify_license(
    public_key_pem: str,
    page_url: str,
    device_code: str,
) -> tuple[bool, str, str]:
    """Crawl the rendered authorization page and validate its matching user object."""
    contact = DEFAULT_OWNER_EMAIL
    try:
        footer_email, users = crawl_authorizations(page_url)
    except (TimeoutException, WebDriverException) as error:
        return False, f"Cannot crawl authorization page: {error}", contact
    contact = footer_email

    try:
        show_progress("3/4 Finding the authorization record for this device...")
        matching_user = next((user for user in users if user.get("deviceHash") == device_hash(device_code)), None)
        if matching_user is None:
            return False, "Authorization record is unavailable.", contact
        payload = json.loads(base64.b64decode(matching_user["license"]).decode("utf-8"))
        signature = base64.b64decode(matching_user["signature"])
        key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(key, Ed25519PublicKey):
            return False, "Authorization public key is invalid.", contact
        key.verify(signature, json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        show_progress("4/4 Verifying authorization signature and expiry...")
        if footer_email.lower() != payload["owner_email"].lower():
            return False, "Authorization owner email does not match.", contact
        if date.fromisoformat(payload["expires_on"]) < date.today():
            return False, "Authorization has expired.", contact
        if payload["device_hash"] != device_hash(device_code):
            return False, "Authorization payload belongs to another device.", contact
    except (KeyError, ValueError, TypeError, json.JSONDecodeError) as error:
        return False, f"Authorization data is malformed: {error}", contact
    except Exception:
        return False, "Authorization signature verification failed.", contact
    try:
        write_authorization_cache(public_key_pem, device_code, payload["expires_on"])
    except OSError as error:
        show_progress(f"Authorization cache was not saved: {error}")
    show_progress("4/4 Authorization verified. Starting the application.")
    return True, "Authorization verified.", contact


def validate_or_exit(settings_path: str | Path | None = None) -> None:
    """Call from an application launcher before loading protected code."""
    settings_file = Path(settings_path or Path(__file__).with_name("runtime-settings.json"))
    settings = json.loads(settings_file.read_text(encoding="utf-8"))
    contact = DEFAULT_OWNER_EMAIL
    try:
        device_code = get_device_code()
        if cache_is_valid(settings["public_key_pem"], device_code):
            show_progress("Authorization cache is valid. Starting the application.")
            return
        show_progress("Authorization cache is unavailable or expired. Online verification is required.")
        valid, message, contact = verify_license(settings["public_key_pem"], settings["page_url"], device_code)
    except RuntimeError as error:
        valid, message = False, f"Cannot read this device UUID: {error}"
    if not valid:
        notification = f"{message}\n\nPlease contact: {contact}"
        try:
            window = Tk()
            window.withdraw()
            window.attributes("-topmost", True)
            messagebox.showerror("Authorization failed", notification, parent=window)
            window.destroy()
        except TclError:
            pass
        print(notification, file=sys.stderr)
        try:
            input("\nPress Enter to close...")
        except EOFError:
            pass
        raise SystemExit(1)