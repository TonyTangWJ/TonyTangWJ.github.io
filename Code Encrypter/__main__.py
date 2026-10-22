"""Desktop tool for issuing signed web licenses and packaging Python applications."""

from __future__ import annotations

import ast
import base64
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import date
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from tkinter import StringVar, Tk, filedialog, messagebox, ttk

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from yaml import safe_dump, safe_load


ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parent
LOG_DIRECTORY = PROJECT_ROOT / "Logs"
ICON_PATH = ROOT / "husky.ico"
DEFAULT_OWNER_EMAIL = "wenjun.a.tang@accenture.cn"
KEY_DIRECTORY = Path(os.environ.get("LOCALAPPDATA", str(ROOT))) / "Python Code Encrypter" / "keys"
LEGACY_KEY_DIRECTORY = ROOT / "keys"


def canonical_payload(payload: dict[str, str]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def hash_device_code(device_code: str) -> str:
    return sha256(device_code.strip().encode("utf-8")).hexdigest()


def project_path(relative_path: str, field_name: str) -> Path:
    path = Path(relative_path)
    if not relative_path or path.is_absolute():
        raise ValueError(f"{field_name} must be a relative path within the project directory.")
    candidate = (PROJECT_ROOT / path).resolve()
    try:
        candidate.relative_to(PROJECT_ROOT)
    except ValueError as error:
        raise ValueError(f"{field_name} must remain within the project directory.") from error
    return candidate


def key_file_prefix(user_name: str) -> str:
    prefix = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", user_name.strip()).rstrip(". ")
    if not prefix:
        raise ValueError("User name cannot be used as a key file name.")
    return prefix


def ensure_key_pair(key_directory: Path, user_name: str) -> tuple[Path, Path]:
    key_directory.mkdir(parents=True, exist_ok=True)
    prefix = key_file_prefix(user_name)
    private_path = key_directory / f"{prefix}-license-private.pem"
    public_path = key_directory / f"{prefix}-license-public.pem"
    generic_private_path = key_directory / "license-private.pem"
    generic_public_path = key_directory / "license-public.pem"
    for legacy_path, destination_path in (
        (LEGACY_KEY_DIRECTORY / "license-private.pem", generic_private_path),
        (LEGACY_KEY_DIRECTORY / "license-public.pem", generic_public_path),
    ):
        if legacy_path.is_file() and not destination_path.exists():
            shutil.move(str(legacy_path), destination_path)
    if LEGACY_KEY_DIRECTORY.is_dir() and not any(LEGACY_KEY_DIRECTORY.iterdir()):
        LEGACY_KEY_DIRECTORY.rmdir()
    if not private_path.exists() and generic_private_path.exists() and generic_public_path.exists():
        shutil.move(str(generic_private_path), private_path)
        shutil.move(str(generic_public_path), public_path)
    if not private_path.exists():
        private_key = Ed25519PrivateKey.generate()
        private_path.write_bytes(private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        public_path.write_bytes(private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    return private_path, public_path


def issue_license(user_name: str, device_code: str, expires_on: str, owner_email: str, key_directory: Path) -> dict[str, str]:
    if not device_code.strip():
        raise ValueError("Device code is required.")
    date.fromisoformat(expires_on)
    private_path, public_path = ensure_key_pair(key_directory, user_name)
    payload = {
        "device_hash": hash_device_code(device_code),
        "expires_on": expires_on,
        "owner_email": owner_email.strip().lower(),
    }
    private_key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    signature = private_key.sign(canonical_payload(payload))
    return {
        "device_hash": payload["device_hash"],
        "license": base64.b64encode(canonical_payload(payload)).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
        "public_key_pem": public_path.read_text(encoding="utf-8"),
    }


def write_authenticator(path: Path, user_name: str, license_data: dict[str, str]) -> None:
    if not user_name.strip():
        raise ValueError("User name is required.")
    existing = safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
    saved_users = existing.get("USER", []) if isinstance(existing, dict) else []
    if saved_users is None:
        saved_users = []
    if isinstance(saved_users, dict):
        saved_users = [saved_users]
    if not isinstance(saved_users, list):
        raise ValueError("authenticator.yml USER must be a list of users.")
    user = {
        "Name": user_name.strip(),
        "DeviceHash": license_data["device_hash"],
        "Signature": license_data["signature"],
        "License": license_data["license"],
    }
    users = [record for record in saved_users if isinstance(record, dict) and record.get("Name") != user["Name"]]
    users.append(user)
    path.write_text(safe_dump({"USER": users}, allow_unicode=True, sort_keys=False), encoding="utf-8")


def next_log_path(log_type: str) -> Path:
    LOG_DIRECTORY.mkdir(exist_ok=True)
    date_stamp = datetime.now().strftime("%Y%m%d")
    for sequence in range(9999, -1, -1):
        if not any(LOG_DIRECTORY.glob(f"{date_stamp}-{sequence:04d}-*.log")):
            return LOG_DIRECTORY / f"{date_stamp}-{sequence:04d}-{log_type}.log"
    raise RuntimeError(f"No log sequence numbers remain for {date_stamp}.")


def run_command(command: list[str], working_directory: Path, log_type: str) -> None:
    log_path = next_log_path(log_type)
    started_at = datetime.now().isoformat(timespec="seconds")
    process = subprocess.Popen(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=working_directory,
    )
    output: list[str] = []
    if process.stdout:
        for line in process.stdout:
            output.append(line)
            print(line, end="", flush=True)
    return_code = process.wait()
    log_path.write_text(
        f"[{started_at}] Command: {subprocess.list2cmdline(command)}\n"
        f"{''.join(output)}"
        f"[{datetime.now().isoformat(timespec='seconds')}] Exit code: {return_code}\n",
        encoding="utf-8",
    )
    if return_code:
        details = "".join(output).strip() or "No command output."
        raise RuntimeError(details)


def copy_project_files(project_directory: Path, entry_point: Path, output: Path) -> None:
    for source_path in project_directory.rglob("*"):
        if "__pycache__" in source_path.parts or source_path.suffix.lower() == ".py":
            continue
        if source_path == output or output in source_path.parents:
            continue
        destination = output / source_path.relative_to(project_directory)
        if source_path.is_dir():
            destination.mkdir(exist_ok=True)
        elif source_path.is_file():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, destination)


def imported_module_names(paths: list[Path]) -> set[str]:
    """Return top-level modules imported by the supplied Python source files."""
    modules: set[str] = set()
    for path in paths:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError) as error:
            raise ValueError(f"Cannot scan imports in {path}: {error}") from error
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                modules.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant):
                function = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
                if function in {"__import__", "import_module"} and isinstance(node.args[0].value, str):
                    modules.add(node.args[0].value.split(".")[0])
    return modules


def third_party_dependencies(source: Path, output: Path) -> list[str]:
    python_files = [
        path for path in source.parent.rglob("*.py")
        if "__pycache__" not in path.parts and output not in path.parents
    ]
    local_modules = {path.relative_to(source.parent).parts[0] for path in python_files}
    local_modules.update(path.stem for path in python_files if path.parent == source.parent)
    standard_modules = set(sys.stdlib_module_names) | set(sys.builtin_module_names)
    dependencies = sorted(imported_module_names([*python_files, ROOT / "license_guard.py"]) - local_modules - standard_modules)
    missing = [name for name in dependencies if importlib.util.find_spec(name) is None]
    if missing:
        raise ValueError(f"Required Python packages are not installed: {', '.join(missing)}")
    return dependencies


def package_application(source: Path, output: Path, license_data: dict[str, str], settings: dict[str, object]) -> None:
    if not source.exists():
        raise ValueError(f"Python entry file does not exist: {source}")
    if not source.is_file() or source.suffix.lower() != ".py":
        raise ValueError("Source path must be a Python entry-point file.")
    if not ICON_PATH.is_file():
        raise ValueError(f"EXE icon is missing: {ICON_PATH}")
    application_output = output / source.parent.name
    application_output.mkdir(parents=True, exist_ok=True)
    (application_output / "main.exe").unlink(missing_ok=True)
    shutil.rmtree(application_output / "_internal", ignore_errors=True)
    build_directory = application_output / ".build"
    shutil.rmtree(build_directory, ignore_errors=True)
    build_directory.mkdir()
    runtime_settings = {
        "public_key_pem": license_data["public_key_pem"], "page_url": settings["page_url"],
    }
    runtime_settings_path = build_directory / "runtime-settings.json"
    runtime_settings_path.write_text(json.dumps(runtime_settings, indent=2), encoding="utf-8")
    version_file = build_directory / "version-info.txt"
    version_file.write_text(
        "VSVersionInfo(\n"
        "  ffi=FixedFileInfo(filevers=(1, 0, 0, 0), prodvers=(1, 0, 0, 0), mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),\n"
        "  kids=[StringFileInfo([StringTable('040904B0', [\n"
        "    StringStruct('CompanyName', 'wenjun.a.tang@accenture.cn'),\n"
        "    StringStruct('FileDescription', 'Protected Python Application'),\n"
        "    StringStruct('OriginalFilename', 'main.exe'),\n"
        "    StringStruct('ProductName', 'Protected Python Application')\n"
        "  ])]), VarFileInfo([VarStruct('Translation', [1033, 1200])])]\n"
        ")\n",
        encoding="utf-8",
    )
    launcher = build_directory / "launcher.py"
    launcher.write_text(
        "from license_guard import validate_or_exit\nvalidate_or_exit()\n"
        "import os\nimport runpy\nimport sys\nfrom pathlib import Path\n"
        "project_directory = Path(sys.executable).parent\n"
        "os.chdir(project_directory)\nsys.path.insert(0, str(project_directory))\n"
        "runpy.run_path(str(Path(__file__).with_name(" + repr(source.name) + ")), run_name='__main__')\n",
        encoding="utf-8",
    )
    data_separator = ";" if sys.platform == "win32" else ":"
    python_files = [
        path for path in source.parent.rglob("*.py")
        if "__pycache__" not in path.parts and output not in path.parents
    ]
    python_data = [
        argument
        for path in python_files
        for argument in ("--add-data", f"{path}{data_separator}{path.relative_to(source.parent).parent or '.'}")
    ]
    dependency_data = [argument for dependency in third_party_dependencies(source, output) for argument in ("--collect-all", dependency)]
    try:
        run_command([
            sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--name", "main",
            "--distpath", str(application_output), "--workpath", str(build_directory / "work"),
            "--specpath", str(build_directory), "--paths", str(ROOT), "--icon", str(ICON_PATH), "--version-file", str(version_file),
            *dependency_data, *python_data, "--add-data", f"{runtime_settings_path}{data_separator}.", str(launcher),
        ], application_output, "pyinstaller")
        copy_project_files(source.parent, source, application_output)
    finally:
        shutil.rmtree(build_directory, ignore_errors=True)


class EncrypterApp:
    def __init__(self, root: Tk) -> None:
        self.root = root
        root.title("Python Code Encrypter")
        root.minsize(640, 1)
        root.columnconfigure(0, weight=1)
        self.values = {
            "user": StringVar(), "device": StringVar(), "expires": StringVar(value=date.today().isoformat()),
            "owner": StringVar(value=DEFAULT_OWNER_EMAIL), "source": StringVar(),
            "output": StringVar(value="Output"),
            "page": StringVar(value="https://tonytangwj.github.io/"),
        }
        frame = ttk.Frame(root, padding=16)
        frame.grid(sticky="nsew")
        frame.columnconfigure(1, weight=1)
        fields = [("User name", "user"), ("Device code", "device"), ("Expiry (YYYY-MM-DD)", "expires"), ("Owner email", "owner"),
                  ("Python entry file (relative)", "source"), ("Encrypted output (relative)", "output"), ("Authorization URL", "page")]
        for row, (label, name) in enumerate(fields):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=4)
            ttk.Entry(frame, textvariable=self.values[name]).grid(row=row, column=1, sticky="ew", padx=(12, 0), pady=4)
            if name in {"source", "output"}:
                ttk.Button(frame, text="...", width=3, command=lambda key=name: self.browse(key)).grid(row=row, column=2, padx=(6, 0))
        ttk.Button(frame, text="Excute", command=self.build).grid(row=len(fields), column=1, sticky="e", pady=(10, 0))

    def browse(self, name: str) -> None:
        if name == "source":
            selected = filedialog.askopenfilename(initialdir=PROJECT_ROOT, filetypes=[("Python", "*.py")])
        else:
            selected = filedialog.askdirectory(initialdir=PROJECT_ROOT)
        if selected:
            try:
                self.values[name].set(str(Path(selected).resolve().relative_to(PROJECT_ROOT)))
            except ValueError:
                messagebox.showerror("Invalid path", "Select a path within the project directory.")

    def build(self) -> None:
        try:
            settings = {name: variable.get().strip() for name, variable in self.values.items()}
            license_data = issue_license(settings["user"], settings["device"], settings["expires"], settings["owner"], KEY_DIRECTORY)
            write_authenticator(ROOT.parent / "authenticator.yml", settings["user"], license_data)
            runtime = {"page_url": settings["page"]}
            package_application(
                project_path(settings["source"], "Python entry file"),
                project_path(settings["output"], "Encrypted output"),
                license_data,
                runtime,
            )
            messagebox.showinfo("Done！", "Done！")
        except Exception as error:
            messagebox.showerror("Build failed", str(error))


if __name__ == "__main__":
    window = Tk()
    EncrypterApp(window)
    window.mainloop()