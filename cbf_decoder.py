#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mercedes / Xentry CBF - first-pass binary decoder
-------------------------------------------------

This tool is deliberately conservative. It does NOT invent a complete CBF
specification. It extracts the parts that can be identified reliably from
the binary:

  * file metadata / SHA256
  * printable strings and their offsets
  * diagnostic-looking byte sequences
  * interesting CBF object names
  * hexadecimal context around interesting objects
  * a JSON report and CSV string table

Usage:
    python cbf_decoder.py CRD.CBF
    python cbf_decoder.py ./CBF_FOLDER --out decoded

The next stage can use several CBF files to infer the common object-header
and object-length structure and then decode relationships such as:

    DT_xxx -> PREP_xxx -> PRES_xxx -> SID/LID

Do not use the extracted "21 xx" patterns as proven diagnostic requests
without validating them against the CBF object relationships and a real ECU.
"""

from pathlib import Path
import argparse
import csv
import hashlib
import json
import re


INTERESTING_PREFIXES = (
    "DT_", "IO", "PREP_", "PRES_", "ADJ_", "FN_", "DJ_",
    "TAB_", "ENUM_", "LID_", "SID_", "ECU_", "JOB_", "DIAG_"
)

INTERESTING_WORDS = (
    "PARTICLE FILTER",
    "SOOT",
    "ASH",
    "REGEN",
    "INJECT",
    "CYLINDER",
    "COOLANT",
    "TEMPERATURE",
    "PRESSURE",
    "ADAPT",
    "RESET",
    "LEARN",
    "LERN",
    "KUPPL",
    "SCHALT",
    "GETRIEBE",
    "TORQUE",
    "LOCK",
)


def read_file(path: Path) -> bytes:
    return path.read_bytes()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def printable_strings(data: bytes, minimum=4):
    """
    Return ASCII printable strings with their binary offsets.
    """
    rx = re.compile(rb"[\x20-\x7e]{%d,}" % minimum)

    for match in rx.finditer(data):
        text = match.group().decode("ascii", errors="replace")
        yield {
            "offset": match.start(),
            "end": match.end(),
            "length": match.end() - match.start(),
            "text": text,
        }


def is_interesting(text: str) -> bool:
    upper = text.upper()

    if upper.startswith(INTERESTING_PREFIXES):
        return True

    return any(word in upper for word in INTERESTING_WORDS)


def hex_context(data: bytes, offset: int, radius=64):
    start = max(0, offset - radius)
    end = min(len(data), offset + radius)

    chunk = data[start:end]

    ascii_text = "".join(
        chr(b) if 32 <= b < 127 else "."
        for b in chunk
    )

    return {
        "start_offset": start,
        "end_offset": end,
        "hex": chunk.hex(" "),
        "ascii": ascii_text,
    }


def find_patterns(data: bytes):
    """
    These are only candidate diagnostic byte patterns.
    They are NOT automatically interpreted as valid requests.
    """

    patterns = {
        "KWP_21": re.compile(rb"\x21[\x00-\xff]"),
        "UDS_22": re.compile(rb"\x22[\x00-\xff]{2}"),
        "UDS_2E": re.compile(rb"\x2e[\x00-\xff]{2,3}"),
        "UDS_31": re.compile(rb"\x31[\x00-\xff]{2,3}"),
        "KWP_3B": re.compile(rb"\x3b[\x00-\xff]{2,3}"),
    }

    result = []

    for name, regex in patterns.items():
        for match in regex.finditer(data):
            result.append({
                "type": name,
                "offset": match.start(),
                "bytes": match.group().hex(" "),
            })

    return sorted(result, key=lambda item: item["offset"])


def find_named_objects(strings):
    """
    Group interesting names by common CBF prefixes.
    """

    groups = {}

    for item in strings:
        if not item.get("interesting"):
            continue

        text = item["text"]
        upper = text.upper()

        prefix = "OTHER"

        for candidate in INTERESTING_PREFIXES:
            if upper.startswith(candidate):
                prefix = candidate
                break

        groups.setdefault(prefix, []).append(item)

    return groups


def inspect_cbf(path: Path, output_dir: Path):
    data = read_file(path)

    strings = []

    for item in printable_strings(data):
        item["interesting"] = is_interesting(item["text"])

        if item["interesting"]:
            item["context"] = hex_context(data, item["offset"])

        strings.append(item)

    interesting = [
        item for item in strings
        if item["interesting"]
    ]

    report = {
        "format": "Mercedes/Xentry CBF - first-pass reverse engineering",
        "file": str(path),
        "size": len(data),
        "sha256": sha256(data),
        "printable_string_count": len(strings),
        "interesting_string_count": len(interesting),
        "interesting_objects": interesting,
        "object_groups": find_named_objects(strings),
        "diagnostic_candidate_patterns": find_patterns(data),
    }

    output_dir.mkdir(parents=True, exist_ok=True)

    stem = path.stem

    json_path = output_dir / f"{stem}.json"
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    csv_path = output_dir / f"{stem}_strings.csv"

    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as f:
        writer = csv.writer(f)

        writer.writerow([
            "offset",
            "end",
            "length",
            "interesting",
            "text",
        ])

        for item in strings:
            writer.writerow([
                item["offset"],
                item["end"],
                item["length"],
                "YES" if item["interesting"] else "",
                item["text"],
            ])

    return report, json_path, csv_path


def main():
    parser = argparse.ArgumentParser(
        description="Mercedes/Xentry CBF binary first-pass decoder"
    )

    parser.add_argument(
        "input",
        help="CBF dosyası veya CBF dosyalarını içeren klasör",
    )

    parser.add_argument(
        "--out",
        default="cbf_decoded",
        help="Çıktı klasörü (varsayılan: cbf_decoded)",
    )

    args = parser.parse_args()

    source = Path(args.input)
    output_dir = Path(args.out)

    if source.is_file():
        files = [source]
    elif source.is_dir():
        files = sorted(source.rglob("*.cbf"))
    else:
        raise SystemExit(f"Girdi bulunamadı: {source}")

    if not files:
        raise SystemExit("CBF dosyası bulunamadı.")

    print(f"{len(files)} CBF dosyası işlenecek.")
    print()

    for path in files:
        try:
            report, json_path, csv_path = inspect_cbf(
                path,
                output_dir,
            )

            print(f"[OK] {path}")
            print(f"     Boyut       : {report['size']:,} byte")
            print(
                f"     İlginç obje : "
                f"{report['interesting_string_count']}"
            )
            print(f"     JSON        : {json_path}")
            print(f"     CSV         : {csv_path}")
            print()

        except Exception as exc:
            print(f"[ERROR] {path}: {exc}")


if __name__ == "__main__":
    main()
