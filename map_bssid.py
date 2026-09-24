"""Map SSID BSSIDs from a C9800 RA trace into an AP inventory CSV."""

from __future__ import annotations

import argparse
import csv
import os
import re
import shutil
import tempfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import TextIO


MAC = r"[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2}"
ASSOCIATION_RE = re.compile(
    rf"(?:Re-)?Association received\. BSSID (?P<bssid>{MAC}), "
    rf"WLAN (?P<ssid>[^,]+), Slot \d+ AP (?P<ap_mac>{MAC}), "
    r"(?P<ap_name>[^,]+), Site tag "
)


def normalize_mac(mac: str) -> str:
    """Return a MAC address without separators and in lowercase."""
    return "".join(character for character in mac.lower() if character.isalnum())


def format_bssid(mac: str) -> str:
    """Return a normalized MAC address in Cisco dotted notation."""
    normalized = normalize_mac(mac)
    return ".".join(normalized[index : index + 4] for index in range(0, 12, 4))


def extract_bssids(
    stream: TextIO, ssid: str
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Collect BSSIDs by AP controller MAC and AP name for one exact SSID."""
    by_mac: dict[str, set[str]] = defaultdict(set)
    by_name: dict[str, set[str]] = defaultdict(set)
    for line in stream:
        association = ASSOCIATION_RE.search(line)
        if not association or association.group("ssid").strip() != ssid:
            continue
        bssid = format_bssid(association.group("bssid"))
        by_mac[normalize_mac(association.group("ap_mac"))].add(bssid)
        by_name[association.group("ap_name").strip()].add(bssid)
    return dict(by_mac), dict(by_name)


def update_inventory(
    inventory_path: Path,
    output_path: Path,
    column_name: str,
    by_mac: dict[str, set[str]],
    by_name: dict[str, set[str]],
) -> tuple[int, int, int, int, Path | None]:
    """Preview changes, confirm in-place writes, and return update statistics."""
    with inventory_path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        required_columns = {"Device Name", "MAC Address"}
        missing_columns = required_columns.difference(reader.fieldnames or ())
        if missing_columns:
            missing = ", ".join(sorted(missing_columns))
            raise ValueError(f"inventory is missing required columns: {missing}")
        fieldnames = list(reader.fieldnames or ())
        rows = list(reader)

    if column_name not in fieldnames:
        fieldnames.append(column_name)

    mapped = 0
    blank = 0
    multiple = 0
    changes: list[tuple[str, str, str]] = []
    for row in rows:
        bssids = by_mac.get(normalize_mac(row["MAC Address"].strip()))
        if not bssids:
            bssids = by_name.get(row["Device Name"].strip(), set())
        before = row.get(column_name, "").strip()
        after = "; ".join(sorted(bssids))
        row[column_name] = after
        if before != after:
            changes.append((row["Device Name"].strip(), before, after))
        if bssids:
            mapped += 1
            multiple += len(bssids) > 1
        else:
            blank += 1

    print(f"\nBSSID changes for {column_name}:")
    if changes:
        for ap_name, before, after in changes:
            print(f"  {ap_name}")
            print(f"    Before: {before or '(blank)'}")
            print(f"    After:  {after or '(blank)'}")
    else:
        print("  No changes.")

    if not changes:
        return mapped, blank, multiple, 0, None

    overwrite_inventory = output_path.resolve() == inventory_path.resolve()
    backup_path: Path | None = None
    if overwrite_inventory:
        try:
            answer = input("\nOverwrite the inventory file? [y/N]: ").strip().lower()
        except EOFError:
            answer = ""
        if answer not in {"y", "yes"}:
            print("Inventory update cancelled.")
            return mapped, blank, multiple, 0, None
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        backup_path = inventory_path.with_name(
            f"{inventory_path.name}.{timestamp}.bak"
        )
        shutil.copy2(inventory_path, backup_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            writer = csv.DictWriter(stream, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        os.replace(temporary_path, output_path)
    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink()

    return mapped, blank, multiple, len(changes), backup_path


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Add an SSID-specific BSSID column to an AP inventory CSV."
    )
    parser.add_argument("trace_file", type=Path, help="C9800 RA trace file")
    parser.add_argument("inventory_file", type=Path, help="AP inventory CSV")
    parser.add_argument(
        "--ssid",
        default="Corp@CLP",
        help="exact WLAN name to map (default: %(default)s)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="output CSV path (default: update the inventory file in place)",
    )
    return parser.parse_args()


def main() -> int:
    """Extract BSSIDs and update the requested inventory CSV."""
    args = parse_args()
    output_path = args.output or args.inventory_file
    column_name = f"{args.ssid} BSSID"
    try:
        with args.trace_file.open(encoding="utf-8", errors="replace") as stream:
            by_mac, by_name = extract_bssids(stream, args.ssid)
        mapped, blank, multiple, changed, backup_path = update_inventory(
            args.inventory_file,
            output_path,
            column_name,
            by_mac,
            by_name,
        )
    except (OSError, ValueError) as error:
        print(f"error: {error}")
        return 1

    print(f"SSID: {args.ssid}")
    print(f"Observed APs: {len(by_mac)}")
    print(f"Mapped inventory APs: {mapped}")
    print(f"Inventory APs without an observed BSSID: {blank}")
    print(f"Inventory APs with multiple observed BSSIDs: {multiple}")
    print(f"Changed inventory APs: {changed}")
    if backup_path:
        print(f"Backup saved to: {backup_path}")
    if changed:
        print(f"CSV saved to: {output_path}")
    else:
        print("CSV was not changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())