#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mercedes / Xentry CBF Parser
============================

Practical reverse-engineering parser for Mercedes CBF files.

What it does:
- Reads CBF binary safely.
- Extracts ASCII and UTF-16LE strings with offsets.
- Detects and indexes named CBF objects (DT_, PREP_, PRES_, ADJ_, FN_, DJ_, IO...).
- Searches the binary for references to object names.
- Detects diagnostic service candidates around object metadata.
- Extracts LID/DID-like numeric identifiers from nearby binary data.
- Produces:
    output/<file>.json
    output/<file>_objects.csv
    output/<file>_strings.csv
    output/<file>_diagnostic_candidates.csv
- Can scan an entire directory recursively.

IMPORTANT:
CBF is an undocumented binary format with several generations/variants.
This parser therefore separates:
  1. OBSERVED binary facts
  2. CANDIDATES / inferred mappings

It does NOT fabricate a factor/offset or claim a request is valid merely
because bytes 21 xx occur in the file.

Usage:
    python cbf_parser.py CRD.CBF
    python cbf_parser.py ./cbf --out ./decoded
    python cbf_parser.py ./cbf --out ./decoded --min-string 3

For EXE:
    pyinstaller --onefile --name CBFParser cbf_parser.py
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import struct
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, Optional


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

OBJECT_PREFIXES = (
    "DT_",
    "PREP_",
    "PRES_",
    "ADJ_",
    "FN_",
    "DJ_",
    "TAB_",
    "ENUM_",
    "IO",
    "JOB_",
    "DIAG_",
)

PARAMETER_WORDS = (
    "PARTICLE FILTER",
    "SOOT",
    "ASH",
    "REGEN",
    "INJECT",
    "INJECTION",
    "INJECTOR",
    "CYLINDER",
    "COOLANT",
    "TEMPERATURE",
    "PRESSURE",
    "ADAPT",
    "ADAPTATION",
    "RESET",
    "LEARN",
    "LERN",
    "TORQUE",
    "LOCK",
    "CLUTCH",
    "SHIFT",
    "GEAR",
    "RPM",
)

SERVICE_NAMES = {
    0x10: "DiagnosticSessionControl / StartDiagnosticSession",
    0x11: "ECUReset",
    0x14: "ClearDiagnosticInformation",
    0x19: "ReadDTCInformation",
    0x21: "ReadDataByLocalIdentifier (KWP)",
    0x22: "ReadDataByIdentifier (UDS)",
    0x23: "ReadMemoryByAddress",
    0x27: "SecurityAccess",
    0x2E: "WriteDataByIdentifier",
    0x2F: "InputOutputControlByIdentifier",
    0x31: "RoutineControl",
    0x34: "RequestDownload",
    0x35: "RequestUpload",
    0x36: "TransferData",
    0x37: "RequestTransferExit",
    0x3B: "WriteDataByLocalIdentifier (KWP)",
}

POSITIVE_RESPONSES = {
    0x50, 0x51, 0x54, 0x59, 0x61, 0x62, 0x63,
    0x67, 0x6E, 0x6F, 0x71, 0x74, 0x75, 0x76,
    0x77, 0x78,
}

NEGATIVE_RESPONSE = 0x7F


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class StringHit:
    offset: int
    end: int
    encoding: str
    text: str
    interesting: bool = False


@dataclass
class ObjectHit:
    name: str
    offset: int
    end: int
    category: str
    description: str = ""
    parameter_score: int = 0
    context_hex: str = ""


@dataclass
class DiagnosticCandidate:
    offset: int
    service: int
    service_name: str
    bytes_hex: str
    candidate_id: Optional[int]
    id_width: Optional[int]
    confidence: str
    reason: str
    nearby_objects: list[str]


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hex_slice(data: bytes, start: int, end: int) -> str:
    return data[start:end].hex(" ")


def printable_ascii(data: bytes, minimum: int) -> Iterable[StringHit]:
    rx = re.compile(rb"[\x20-\x7E]{%d,}" % minimum)

    for m in rx.finditer(data):
        text = m.group().decode("ascii", errors="replace")
        yield StringHit(
            offset=m.start(),
            end=m.end(),
            encoding="ascii",
            text=text,
            interesting=is_interesting(text),
        )


def printable_utf16le(data: bytes, minimum: int) -> Iterable[StringHit]:
    # UTF-16LE ASCII-range text, useful for some CBF variants.
    rx = re.compile(
        rb"(?:[\x20-\x7E]\x00){%d,}" % minimum
    )

    for m in rx.finditer(data):
        raw = m.group()
        try:
            text = raw.decode("utf-16le")
        except UnicodeDecodeError:
            continue

        yield StringHit(
            offset=m.start(),
            end=m.end(),
            encoding="utf-16le",
            text=text,
            interesting=is_interesting(text),
        )


def is_interesting(text: str) -> bool:
    u = text.upper()

    if u.startswith(OBJECT_PREFIXES):
        return True

    return any(word in u for word in PARAMETER_WORDS)


def object_category(name: str) -> str:
    u = name.upper()

    for prefix in OBJECT_PREFIXES:
        if u.startswith(prefix):
            return prefix.rstrip("_")

    return "OTHER"


def parameter_score(name: str) -> int:
    u = name.upper()

    score = 0

    if u.startswith(OBJECT_PREFIXES):
        score += 2

    for word in PARAMETER_WORDS:
        if word in u:
            score += 2

    if "PARTICLE FILTER" in u or "SOOT" in u:
        score += 5

    if "INJECT" in u:
        score += 4

    if "RESET" in u or "ADAPT" in u:
        score += 4

    return score


def nearby_texts(
    strings: list[StringHit],
    offset: int,
    radius: int = 512,
) -> list[StringHit]:
    lo = offset - radius
    hi = offset + radius

    return [
        s for s in strings
        if lo <= s.offset <= hi
    ]


def context_hex(data: bytes, offset: int, radius: int = 48) -> str:
    a = max(0, offset - radius)
    b = min(len(data), offset + radius)
    return data[a:b].hex(" ")


# ---------------------------------------------------------------------------
# CBF object discovery
# ---------------------------------------------------------------------------

def discover_objects(
    data: bytes,
    strings: list[StringHit],
) -> list[ObjectHit]:

    objects: list[ObjectHit] = []

    for s in strings:
        if not s.interesting:
            continue

        name = s.text.strip()

        # Avoid treating long English/German descriptions as object names.
        if len(name) > 180:
            continue

        category = object_category(name)

        nearby = nearby_texts(strings, s.offset, 256)

        description_candidates = [
            x.text for x in nearby
            if x.text != name
            and not x.text.startswith(OBJECT_PREFIXES)
            and len(x.text) >= 8
        ]

        description = ""
        if description_candidates:
            # Nearest candidate is generally the most useful.
            description = min(
                description_candidates,
                key=lambda t: abs(
                    next(
                        x.offset for x in nearby
                        if x.text == t
                    ) - s.offset
                ),
            )

        objects.append(
            ObjectHit(
                name=name,
                offset=s.offset,
                end=s.end,
                category=category,
                description=description,
                parameter_score=parameter_score(name),
                context_hex=context_hex(data, s.offset),
            )
        )

    # De-duplicate identical object names at the same offset.
    unique = {}
    for obj in objects:
        unique[(obj.offset, obj.name)] = obj

    return sorted(
        unique.values(),
        key=lambda x: (x.offset, x.name),
    )


# ---------------------------------------------------------------------------
# Diagnostic candidate discovery
# ---------------------------------------------------------------------------

def nearby_object_names(
    objects: list[ObjectHit],
    offset: int,
    radius: int = 1024,
) -> list[str]:
    names = []

    for obj in objects:
        if abs(obj.offset - offset) <= radius:
            names.append(obj.name)

    return names[:20]


def candidate_reason(
    service: int,
    candidate_id: Optional[int],
    nearby: list[str],
) -> tuple[str, str]:

    if nearby:
        if any(
            any(k in n.upper() for k in (
                "PREP_", "PRES_", "DT_", "IO"
            ))
            for n in nearby
        ):
            return (
                "medium",
                "Diagnostic-looking bytes occur near named CBF data objects.",
            )

    if service == 0x21:
        return (
            "low",
            "0x21 is a KWP local-identifier service candidate; object linkage "
            "has not been proven at this offset.",
        )

    if service == 0x22:
        return (
            "low",
            "0x22 is a UDS data-identifier service candidate; object linkage "
            "has not been proven at this offset.",
        )

    return (
        "low",
        "Diagnostic service byte candidate; requires CBF object linkage.",
    )


def discover_diagnostic_candidates(
    data: bytes,
    objects: list[ObjectHit],
) -> list[DiagnosticCandidate]:

    results: list[DiagnosticCandidate] = []

    # Search candidate service bytes. This is intentionally conservative.
    services = set(SERVICE_NAMES.keys())

    for offset, byte in enumerate(data):
        if byte not in services:
            continue

        # Avoid reporting every random byte as a diagnostic service.
        # Require some structure in the following bytes.
        if offset + 1 >= len(data):
            continue

        following = data[offset: min(len(data), offset + 8)]

        candidate_id = None
        id_width = None

        if byte in (0x21, 0x3B, 0x22, 0x2E, 0x2F):
            if byte in (0x21, 0x3B):
                # KWP local identifier is commonly one byte.
                candidate_id = data[offset + 1]
                id_width = 1
            else:
                # UDS identifiers are commonly 2 bytes.
                if offset + 2 < len(data):
                    candidate_id = (
                        (data[offset + 1] << 8)
                        | data[offset + 2]
                    )
                    id_width = 2

        nearby = nearby_object_names(objects, offset)

        confidence, reason = candidate_reason(
            byte,
            candidate_id,
            nearby,
        )

        results.append(
            DiagnosticCandidate(
                offset=offset,
                service=byte,
                service_name=SERVICE_NAMES[byte],
                bytes_hex=following.hex(" "),
                candidate_id=candidate_id,
                id_width=id_width,
                confidence=confidence,
                reason=reason,
                nearby_objects=nearby,
            )
        )

    # There can be tens of thousands of random candidates. Keep only
    # candidates near interesting object names or a smaller sample otherwise.
    linked = [
        r for r in results
        if r.nearby_objects
    ]

    if linked:
        return linked

    return results[:5000]


# ---------------------------------------------------------------------------
# Object relationship candidates
# ---------------------------------------------------------------------------

def build_relationships(
    objects: list[ObjectHit],
    strings: list[StringHit],
) -> list[dict]:

    relationships = []

    for obj in objects:
        nearby = nearby_texts(strings, obj.offset, 1024)

        related = []

        for other in nearby:
            if other.offset == obj.offset:
                continue

            if other.interesting:
                related.append({
                    "name": other.text,
                    "offset": other.offset,
                    "distance": other.offset - obj.offset,
                })

        # Keep only useful nearby named objects.
        related = sorted(
            related,
            key=lambda x: abs(x["distance"]),
        )[:20]

        relationships.append({
            "object": obj.name,
            "offset": obj.offset,
            "related_candidates": related,
        })

    return relationships


# ---------------------------------------------------------------------------
# Full file parser
# ---------------------------------------------------------------------------

def parse_file(
    path: Path,
    minimum_string: int = 4,
) -> dict:

    data = path.read_bytes()

    strings = list(
        printable_ascii(data, minimum_string)
    )

    # Add UTF-16 strings, avoiding exact duplicates.
    existing = {
        (s.offset, s.text)
        for s in strings
    }

    for s in printable_utf16le(data, minimum_string):
        if (s.offset, s.text) not in existing:
            strings.append(s)

    strings.sort(key=lambda s: s.offset)

    objects = discover_objects(data, strings)

    diagnostics = discover_diagnostic_candidates(
        data,
        objects,
    )

    relationships = build_relationships(
        objects,
        strings,
    )

    return {
        "parser": {
            "name": "Mercedes/Xentry CBF Parser",
            "version": "0.2.0",
            "mode": "conservative reverse-engineering",
        },
        "file": {
            "name": path.name,
            "path": str(path),
            "size": len(data),
            "sha256": sha256(data),
        },
        "strings": [
            asdict(s)
            for s in strings
        ],
        "objects": [
            asdict(o)
            for o in objects
        ],
        "diagnostic_candidates": [
            asdict(d)
            for d in diagnostics
        ],
        "relationships": relationships,
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_csv(
    path: Path,
    rows: list[dict],
    fields: list[str],
):
    with path.open(
        "w",
        newline="",
        encoding="utf-8-sig",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fields,
            extrasaction="ignore",
        )

        writer.writeheader()

        for row in rows:
            writer.writerow(row)


def write_report(
    result: dict,
    output_dir: Path,
):
    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    stem = Path(result["file"]["name"]).stem

    json_path = output_dir / f"{stem}.json"

    json_path.write_text(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    objects_path = output_dir / f"{stem}_objects.csv"

    write_csv(
        objects_path,
        result["objects"],
        [
            "name",
            "offset",
            "end",
            "category",
            "description",
            "parameter_score",
            "context_hex",
        ],
    )

    strings_path = output_dir / f"{stem}_strings.csv"

    write_csv(
        strings_path,
        result["strings"],
        [
            "offset",
            "end",
            "encoding",
            "text",
            "interesting",
        ],
    )

    diag_path = (
        output_dir /
        f"{stem}_diagnostic_candidates.csv"
    )

    diag_rows = []

    for row in result["diagnostic_candidates"]:
        diag_rows.append({
            "offset": row["offset"],
            "service": f"0x{row['service']:02X}",
            "service_name": row["service_name"],
            "candidate_id": (
                ""
                if row["candidate_id"] is None
                else (
                    f"0x{row['candidate_id']:02X}"
                    if row["id_width"] == 1
                    else f"0x{row['candidate_id']:04X}"
                )
            ),
            "id_width": row["id_width"] or "",
            "confidence": row["confidence"],
            "reason": row["reason"],
            "bytes_hex": row["bytes_hex"],
            "nearby_objects": " | ".join(
                row["nearby_objects"]
            ),
        })

    write_csv(
        diag_path,
        diag_rows,
        [
            "offset",
            "service",
            "service_name",
            "candidate_id",
            "id_width",
            "confidence",
            "reason",
            "bytes_hex",
            "nearby_objects",
        ],
    )

    return (
        json_path,
        objects_path,
        strings_path,
        diag_path,
    )


# ---------------------------------------------------------------------------
# Directory scan
# ---------------------------------------------------------------------------

def scan(
    input_path: Path,
    output_dir: Path,
    minimum_string: int,
):
    if input_path.is_file():
        files = [input_path]
    elif input_path.is_dir():
        files = sorted(
            p for p in input_path.rglob("*")
            if p.is_file()
            and p.suffix.lower() == ".cbf"
        )
    else:
        raise FileNotFoundError(
            f"Girdi bulunamadi: {input_path}"
        )

    if not files:
        raise RuntimeError(
            "CBF dosyasi bulunamadi."
        )

    summary = []

    for file_path in files:
        print(f"[+] Parsing: {file_path}")

        result = parse_file(
            file_path,
            minimum_string,
        )

        paths = write_report(
            result,
            output_dir,
        )

        summary.append({
            "file": file_path.name,
            "size": result["file"]["size"],
            "objects": len(result["objects"]),
            "strings": len(result["strings"]),
            "diagnostic_candidates": len(
                result["diagnostic_candidates"]
            ),
        })

        print(
            f"    Objects: "
            f"{len(result['objects'])}"
        )

        print(
            f"    Diagnostic candidates: "
            f"{len(result['diagnostic_candidates'])}"
        )

        print(
            f"    JSON: {paths[0]}"
        )

    summary_path = output_dir / "cbf_summary.json"

    summary_path.write_text(
        json.dumps(
            {
                "files_processed": len(summary),
                "files": summary,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print()
    print(
        f"[OK] {len(summary)} CBF file(s) processed."
    )
    print(
        f"[OK] Summary: {summary_path}"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Mercedes/Xentry CBF conservative binary parser"
        )
    )

    parser.add_argument(
        "input",
        help=(
            "CBF dosyasi veya CBF dosyalarinin bulundugu klasor"
        ),
    )

    parser.add_argument(
        "--out",
        default="decoded",
        help="cikti klasoru",
    )

    parser.add_argument(
        "--min-string",
        type=int,
        default=4,
        help="Minimum ASCII string uzunlugu",
    )

    args = parser.parse_args()

    scan(
        Path(args.input),
        Path(args.out),
        args.min_string,
    )


if __name__ == "__main__":
    main()
