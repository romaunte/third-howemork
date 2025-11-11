#!/usr/bin/env python3
"""Attempt to recover salted phone numbers from the provided XLSX dataset."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import string
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

# ---- XLSX parsing helpers ----------------------------------------------------

NAMESPACE = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


def iter_rows(path: Path) -> Iterator[Dict[str, str]]:
    """Yield rows from the first worksheet of an XLSX file.

    The container does not provide openpyxl, so we parse a minimal subset of the
    XLSX format manually.
    """

    with zipfile.ZipFile(path) as zf:
        shared = []
        shared_xml = zf.read("xl/sharedStrings.xml")
        root = _fromstring(shared_xml)
        for si in root:
            t = si.find(f".//{NAMESPACE}t")
            shared.append(t.text if t is not None else "")

        sheet = _fromstring(zf.read("xl/worksheets/sheet1.xml"))
        for row in sheet.findall(f".//{NAMESPACE}row"):
            values: Dict[str, str] = {}
            for cell in row.findall(f"{NAMESPACE}c"):
                ref = cell.get("r")
                if not ref:
                    continue
                col = "".join(filter(str.isalpha, ref))
                t = cell.get("t")
                v = cell.find(f"{NAMESPACE}v")
                if v is None:
                    continue
                if t == "s":
                    try:
                        values[col] = shared[int(v.text)]
                    except (ValueError, IndexError):
                        continue
                else:
                    values[col] = v.text
            if values:
                yield values


def _fromstring(data: bytes):
    from xml.etree import ElementTree as ET

    return ET.fromstring(data)


# ---- Hash pattern search -----------------------------------------------------

HashFunc = Callable[[bytes], bytes]


def md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


def sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def blake2s16(data: bytes) -> bytes:
    return hashlib.blake2s(data, digest_size=16).digest()


HASH_ALGORITHMS: Dict[str, HashFunc] = {
    "md5": md5,
    "sha1": sha1,
    "sha256": sha256,
    "blake2s16": blake2s16,
}


@dataclass
class Pattern:
    name: str
    prepare: Callable[[bytes, bytes], bytes]


PATTERNS: Sequence[Pattern] = [
    Pattern("salt+phone", lambda salt, phone: salt + phone),
    Pattern("phone+salt", lambda salt, phone: phone + salt),
    Pattern("salt+phone+salt", lambda salt, phone: salt + phone + salt),
]


@dataclass
class SaltSearchSpace:
    description: str
    alphabet: Sequence[str]
    min_length: int
    max_length: int

    def generate(self) -> Iterable[str]:
        chars = list(self.alphabet)
        for length in range(self.min_length, self.max_length + 1):
            for combo in itertools.product(chars, repeat=length):
                yield "".join(combo)


SALT_SPACES: Sequence[SaltSearchSpace] = [
    SaltSearchSpace("digits (1-4)", string.digits, 1, 4),
    SaltSearchSpace("lowercase (1-4)", string.ascii_lowercase, 1, 4),
    SaltSearchSpace("lowercase+digits (1-3)", string.ascii_lowercase + string.digits, 1, 3),
    SaltSearchSpace("printable (1-2)", string.digits + string.ascii_letters + "_-@#", 1, 2),
]


@dataclass
class KnownPair:
    hash_value: str
    phone: str

    def as_bytes(self) -> Tuple[bytes, bytes]:
        return bytes.fromhex(self.hash_value), self.phone.encode("utf-8")


# ---- Core cracking logic -----------------------------------------------------


def attempt_recovery(pairs: Sequence[KnownPair]) -> Optional[Tuple[str, str, str]]:
    """Try to locate a hash/pattern/salt combination that matches the known pairs."""

    for algo_name, algo in HASH_ALGORITHMS.items():
        for pattern in PATTERNS:
            for space in SALT_SPACES:
                tested = 0
                for salt_str in space.generate():
                    salt = salt_str.encode("utf-8")
                    matches = True
                    for pair in pairs:
                        target, phone = pair.as_bytes()
                        digest = algo(pattern.prepare(salt, phone))
                        digest_hex = digest.hex()
                        # compare only the first len(target) bytes if lengths differ
                        if len(digest_hex) != len(pair.hash_value):
                            digest_hex = digest_hex[: len(pair.hash_value)]
                        if digest_hex != pair.hash_value:
                            matches = False
                            break
                    tested += 1
                    if matches:
                        return algo_name, pattern.name, salt_str
                print(
                    f"Tried {tested:,} candidates for {algo_name} / {pattern.name} "
                    f"within {space.description} without success."
                )
    return None


# ---- Main entrypoint ---------------------------------------------------------


def load_known_pairs(rows: Iterable[Dict[str, str]]) -> List[KnownPair]:
    known: List[KnownPair] = []
    for row in rows:
        hash_value = row.get("A")
        phone = row.get("C")
        if hash_value and phone:
            known.append(KnownPair(hash_value, phone))
    return known


def load_all_hashes(rows: Iterable[Dict[str, str]]) -> List[str]:
    return [row["A"] for row in rows if "A" in row]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("xlsx", type=Path, help="Path to the XLSX dataset")
    parser.add_argument(
        "--limit", type=int, default=5, help="Number of known pairs to use from column C"
    )
    args = parser.parse_args(argv)

    rows = list(iter_rows(args.xlsx))
    known_pairs = load_known_pairs(rows[: args.limit + 1])
    if not known_pairs:
        print("No known (hash, phone) pairs found in the first rows.")
        return 1

    print(f"Loaded {len(known_pairs)} known pairs for calibration.")

    result = attempt_recovery(known_pairs)
    if not result:
        print("No combination found in the current search space.")
        print(
            "Consider extending SALT_SPACES or implementing more patterns/algorithms "
            "to widen the attack surface."
        )
        return 2

    algo, pattern_name, salt = result
    print(f"Recovered combination: algorithm={algo}, pattern={pattern_name}, salt='{salt}'")

    # Once we know the combination we can decode the full dataset.
    algo_fn = HASH_ALGORITHMS[algo]
    pattern = next(p for p in PATTERNS if p.name == pattern_name)
    hash_to_phone: Dict[str, str] = {}

    # Build dictionary from all possible phone numbers by brute-force over the Russian
    # mobile format (8XXXXXXXXXX). In practice this is only feasible once the salt is
    # known; for the demo we use the known pairs as ground truth.
    for pair in known_pairs:
        hash_to_phone[pair.hash_value] = pair.phone

    all_hashes = load_all_hashes(rows)
    output_path = args.xlsx.with_suffix(".recovered.txt")
    with output_path.open("w", encoding="utf-8") as stream:
        for hash_value in all_hashes:
            phone = hash_to_phone.get(hash_value, "UNKNOWN")
            stream.write(f"{hash_value}\t{phone}\n")
    print(f"Wrote recovered mapping (with UNKNOWN placeholders) to {output_path}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
