from hashlib import sha256
from json import load
from pathlib import Path
from re import subn


ROOT = Path(__file__).parent
CONFIG_PATH = ROOT / "device-config.json"
INDEX_PATH = ROOT / "index.html"
HASH_PATTERN = r'data-device-hash="[^"]*"'


def hash_device_id(device_id: str) -> str:
    return sha256(device_id.encode("utf-8")).hexdigest()


def main() -> None:
    with CONFIG_PATH.open(encoding="utf-8") as config_file:
        device_id = load(config_file)["deviceId"]

    device_hash = hash_device_id(device_id)
    index_html = INDEX_PATH.read_text(encoding="utf-8")
    updated_html, replacements = subn(
        HASH_PATTERN,
        f'data-device-hash="{device_hash}"',
        index_html,
        count=1,
    )

    if replacements != 1:
        raise ValueError("Expected exactly one data-device-hash attribute in index.html.")

    INDEX_PATH.write_text(updated_html, encoding="utf-8")


if __name__ == "__main__":
    main()