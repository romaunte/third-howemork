#!/usr/bin/env python3
"""Use hashcat to attack salted phone hashes from the provided XLSX dataset."""

from __future__ import annotations

import argparse
import itertools
import shutil
import string
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

NAMESPACE = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


# ---------------------------------------------------------------------------
# XLSX parsing helpers (minimal replacement for openpyxl)
# ---------------------------------------------------------------------------

def iter_rows(path: Path) -> Iterator[Dict[str, str]]:
    """Yield rows from the first worksheet of an XLSX file."""

    with zipfile.ZipFile(path) as zf:
        shared_strings = []
        shared_xml = zf.read("xl/sharedStrings.xml")
        root = _fromstring(shared_xml)
        for si in root:
            t = si.find(f".//{NAMESPACE}t")
            shared_strings.append(t.text if t is not None else "")

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
                        values[col] = shared_strings[int(v.text)]
                    except (ValueError, IndexError):
                        continue
                else:
                    values[col] = v.text
            if values:
                yield values


def _fromstring(data: bytes):
    from xml.etree import ElementTree as ET

    return ET.fromstring(data)


# ---------------------------------------------------------------------------
# CLI configuration structures
# ---------------------------------------------------------------------------


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


SALT_SPACES: Dict[str, SaltSearchSpace] = {
    "digits1-4": SaltSearchSpace("digits (1-4)", string.digits, 1, 4),
    "lower1-4": SaltSearchSpace("lowercase letters (1-4)", string.ascii_lowercase, 1, 4),
    "alnum1-3": SaltSearchSpace(
        "alphanumeric (1-3)", string.ascii_lowercase + string.digits, 1, 3
    ),
    "printable1-2": SaltSearchSpace(
        "printable subset (1-2)", string.digits + string.ascii_letters + "_-@#", 1, 2
    ),
}

PATTERN_TO_ATTACK_MODE = {
    "phone": 3,  # mask attack: hashcat -a 3 hash.txt mask
    "salt+phone": 6,  # hybrid wordlist + mask: hashcat -a 6 hash.txt salts mask
    "phone+salt": 7,  # hybrid mask + wordlist: hashcat -a 7 hash.txt mask salts
}


@dataclass
class KnownPair:
    hash_value: str
    phone: str


# ---------------------------------------------------------------------------
# Hashcat invocation helpers
# ---------------------------------------------------------------------------


def ensure_hashcat(path: str) -> str:
    resolved = shutil.which(path)
    if resolved is None:
        raise FileNotFoundError(
            f"Unable to locate '{path}'. Ensure hashcat is installed and available in PATH."
        )
    return resolved


def write_hash_file(path: Path, hashes: Sequence[str]) -> None:
    path.write_text("\n".join(hashes) + "\n", encoding="utf-8")


def write_salt_file(path: Path, salts: Iterable[str]) -> int:
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for salt in salts:
            handle.write(f"{salt}\n")
            count += 1
    return count


def parse_outfile(path: Path) -> Dict[str, str]:
    cracked: Dict[str, str] = {}
    if not path.exists():
        return cracked
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        if ":" not in line:
            continue
        hash_part, plain = line.split(":", 1)
        cracked[hash_part.strip()] = plain.strip()
    return cracked


def run_hashcat(
    *,
    hashcat: str,
    hash_file: Path,
    attack_mode: int,
    hash_type: int,
    mask: str,
    salts_file: Optional[Path],
    extra_args: Sequence[str],
) -> Tuple[int, Dict[str, str], subprocess.CompletedProcess[str]]:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        outfile = tmp_path / "hashcat.out"
        potfile = tmp_path / "hashcat.pot"

        cmd = [
            hashcat,
            "-m",
            str(hash_type),
            "-a",
            str(attack_mode),
            "--potfile-path",
            str(potfile),
            "--outfile",
            str(outfile),
            "--outfile-format",
            "2",  # hash:plain
            str(hash_file),
        ]

        if attack_mode == 6:  # salt+phone
            if salts_file is None:
                raise ValueError("salt+phone pattern requires a salts file")
            cmd.append(str(salts_file))
            cmd.append(mask)
        elif attack_mode == 7:  # phone+salt
            if salts_file is None:
                raise ValueError("phone+salt pattern requires a salts file")
            cmd.append(mask)
            cmd.append(str(salts_file))
        else:  # mask only
            cmd.append(mask)

        cmd.extend(extra_args)

        result = subprocess.run(
            cmd,
            check=False,
            text=True,
            capture_output=True,
        )

        cracked = parse_outfile(outfile)
        return result.returncode, cracked, result


# ---------------------------------------------------------------------------
# Business logic
# ---------------------------------------------------------------------------


def load_known_pairs(rows: Iterable[Dict[str, str]], limit: int) -> List[KnownPair]:
    known: List[KnownPair] = []
    for row in rows:
        if len(known) >= limit:
            break
        hash_value = row.get("A")
        phone = row.get("C")
        if hash_value and phone:
            known.append(KnownPair(hash_value, phone))
    return known


def load_all_hashes(rows: Iterable[Dict[str, str]]) -> List[str]:
    hashes: List[str] = []
    for row in rows:
        hash_value = row.get("A")
        if hash_value:
            hashes.append(hash_value)
    return hashes


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("xlsx", type=Path, help="Path to the XLSX dataset")
    parser.add_argument(
        "--hashcat",
        default="hashcat",
        help="Path to the hashcat binary (default: hashcat in PATH)",
    )
    parser.add_argument(
        "--hash-type",
        type=int,
        action="append",
        required=True,
        help="Hashcat hash-type identifier to test (can be repeated)",
    )
    parser.add_argument(
        "--pattern",
        choices=sorted(PATTERN_TO_ATTACK_MODE),
        default="salt+phone",
        help="How the salt is combined with the phone number",
    )
    parser.add_argument(
        "--salt-space",
        choices=sorted(SALT_SPACES),
        action="append",
        default=["digits1-4"],
        help="Named salt search spaces to combine (repeat for more spaces)",
    )
    parser.add_argument(
        "--mask",
        default="8?d?d?d?d?d?d?d?d?d?d",
        help="Hashcat mask describing the phone format",
    )
    parser.add_argument(
        "--limit-known",
        type=int,
        default=5,
        help="Number of known pairs from column C to validate against",
    )
    parser.add_argument(
        "--extra-arg",
        action="append",
        default=[],
        help="Extra arguments to append to the hashcat command (repeatable)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Where to write cracked results (default: alongside the XLSX file)",
    )
    args = parser.parse_args(argv)

    try:
        hashcat_path = ensure_hashcat(args.hashcat)
    except FileNotFoundError as exc:
        print(exc)
        return 127

    rows = list(iter_rows(args.xlsx))
    if not rows:
        print("No rows found in the workbook.")
        return 1

    known_pairs = load_known_pairs(rows, args.limit_known)
    if not known_pairs:
        print("Unable to locate known plaintext samples in column C.")
        return 1

    all_hashes = load_all_hashes(rows)
    if not all_hashes:
        print("No hash values discovered in column A.")
        return 1

    salts: List[str] = []
    for space_name in args.salt_space:
        space = SALT_SPACES[space_name]
        salts.extend(space.generate())
    salts = sorted(set(salts))

    if args.pattern != "phone" and not salts:
        print("Salted patterns require at least one salt candidate.")
        return 1

    if args.output is None:
        args.output = args.xlsx.with_suffix(".hashcat.txt")

    print(f"Loaded {len(known_pairs)} known pairs for validation.")
    print(f"Discovered {len(all_hashes)} hashed entries in the dataset.")
    print(
        f"Generated {len(salts)} candidate salts across {len(args.salt_space)} search spaces."
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        known_hash_file = tmp / "known.hashes"
        all_hash_file = tmp / "all.hashes"
        salts_file = tmp / "salts.txt"

        write_hash_file(known_hash_file, [kp.hash_value for kp in known_pairs])
        write_hash_file(all_hash_file, all_hashes)
        if args.pattern != "phone":
            count = write_salt_file(salts_file, salts)
            if count == 0:
                print("Salted pattern selected but no salts produced.")
                return 1

        for hash_type in args.hash_type:
            attack_mode = PATTERN_TO_ATTACK_MODE[args.pattern]
            print(
                f"\nRunning hashcat (m={hash_type}, a={attack_mode}, pattern={args.pattern}) "
                f"against {known_hash_file.name} to validate salt candidates..."
            )

            exit_code, cracked_known, process = run_hashcat(
                hashcat=hashcat_path,
                hash_file=known_hash_file,
                attack_mode=attack_mode,
                hash_type=hash_type,
                mask=args.mask,
                salts_file=salts_file if args.pattern != "phone" else None,
                extra_args=args.extra_arg,
            )

            sys.stdout.write(process.stdout)
            sys.stderr.write(process.stderr)

            if len(cracked_known) < len(known_pairs):
                print(
                    f"Failed to crack all {len(known_pairs)} known samples (cracked {len(cracked_known)})."
                )
                continue

            print(
                f"Validation succeeded with hash-type {hash_type}; cracking full dataset next..."
            )

            exit_code, cracked_all, process = run_hashcat(
                hashcat=hashcat_path,
                hash_file=all_hash_file,
                attack_mode=attack_mode,
                hash_type=hash_type,
                mask=args.mask,
                salts_file=salts_file if args.pattern != "phone" else None,
                extra_args=args.extra_arg,
            )

            sys.stdout.write(process.stdout)
            sys.stderr.write(process.stderr)

            if not cracked_all:
                print("Hashcat did not recover any entries from the full dataset.")
                continue

            print(
                f"Hashcat recovered {len(cracked_all)} of {len(all_hashes)} entries. "
                f"Writing results to {args.output}."
            )

            with args.output.open("w", encoding="utf-8") as handle:
                for hash_value in all_hashes:
                    phone = cracked_all.get(hash_value, "UNKNOWN")
                    handle.write(f"{hash_value}\t{phone}\n")

            print("Done.")
            return 0

    print("Hashcat was unable to crack the dataset with the provided parameters.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
