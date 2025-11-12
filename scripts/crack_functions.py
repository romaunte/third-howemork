from pathlib import Path
import pandas as pd
import shutil
import re
import subprocess

BASE_DIR = Path(__file__).parent
HASHCAT_EXE = Path(r"E:\ProgramFiles\hashcat-7.1.2\hashcat.exe")
MASK_LENGTH = 11

def mask_for_salt_type(salt_type: str, length: int = MASK_LENGTH) -> str:
    if salt_type == "numeric":
        return "?d" * length
    if salt_type == "alphabetic":
        return "?d" * MASK_LENGTH + "?l" * length
    if salt_type == "alphanumeric":
        return "?d" * MASK_LENGTH + "?a" * length
    raise ValueError(f"Unknown salt type: {salt_type}")

def compute_subtracted_value(found_password, known_value, salt_type):
    if found_password is None or (isinstance(found_password, float) and pd.isna(found_password)):
        return pd.NA
    try:
        s_known = str(int(known_value))
    except Exception:
        return pd.NA

    try:
        found_str = str(found_password)
    except Exception:
        return pd.NA
    if found_str == "":
        return pd.NA

    if salt_type == "numeric":
        try:
            return str(int(found_str) - int(s_known))
        except Exception:
            return pd.NA
    else:
        if found_str.startswith(s_known):
            suffix = found_str[len(s_known):]
            if suffix == "":
                return pd.NA
            return suffix
        return pd.NA

def save_excel_with_first_header(df, filename):
    with pd.ExcelWriter(filename, engine='xlsxwriter') as writer:
        df.to_excel(writer, sheet_name='Sheet1', index=False, header=False, startrow=1)
        worksheet = writer.sheets['Sheet1']
        worksheet.write(0, 0, df.columns[0])

def remove_path(path):
    path_obj = Path(path)
    if path_obj.exists():
        if path_obj.is_file():
            path_obj.unlink()
            print(f"File '{path}' deleted")
        elif path_obj.is_dir():
            shutil.rmtree(path_obj)
            print(f"Folder '{path}' deleted")
    else:
        print(f"Path '{path}' is non existing")

def detect_single_hash_type(h: str):
    length = len(h)
    types = {
        32: ("md5", 0),
        40: ("sha1", 100),
        64: ("sha256", 1400),
        128: ("sha512", 1700),
    }
    return types.get(length, None)

def run_deanonymization(input_path: Path, salt_type: str = "numeric", mask_length: int = MASK_LENGTH):
    HASHES_TXT = BASE_DIR / "hashes.txt"
    OUTPUT_RAW = BASE_DIR / "outfile.txt"
    TEMP_DIR = BASE_DIR / "temporary_folder"
    TEMP_DIR.mkdir(exist_ok=True)

    df = pd.read_excel(input_path, dtype=str).fillna("")
    lines = [str(x).strip().lower() for x in df.iloc[:, 0].astype(str)]

    hex_re = re.compile(r"^[0-9a-fA-F]+$")
    first_valid = next((h for h in lines if hex_re.fullmatch(h)), None)
    if not first_valid:
        raise ValueError("No valid hashes.")

    detected = detect_single_hash_type(first_valid)
    if detected is None:
        raise ValueError(f"Algorithm detection error: {len(first_valid)}")

    hash_name, hashcat_mode = detected
    print(f"Detected hash type: {hash_name}, using hashcat -m {hashcat_mode}")

    hashes = [h for h in lines if hex_re.fullmatch(h)]
    with open(HASHES_TXT, "w", newline="\n", encoding="utf-8") as f:
        f.write("\n".join(hashes))

    known_numbers = df.iloc[:5, 2].astype(int).tolist()
    mask = mask_for_salt_type(salt_type, length=mask_length)
    cmd = [
        str(HASHCAT_EXE),
        "-m", str(hashcat_mode),
        "-a", "3",
        "--potfile-disable",
        "-o", str(OUTPUT_RAW),
        "-O",
        str(HASHES_TXT),
        mask
    ]

    print("Hashcat launched.")
    subprocess.run(cmd, cwd=HASHCAT_EXE.parent)
    print("Hashcat finished.")

    found = {}
    if OUTPUT_RAW.exists() and OUTPUT_RAW.stat().st_size > 0:
        with open(OUTPUT_RAW, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.rstrip("\r\n")
                if not line:
                    continue
                h, p = line.split(":", 1)
                found[h.lower()] = p

    rows_full = []
    hash_iter = iter(hashes)
    for line in lines:
        if hex_re.fullmatch(str(line).strip().lower()):
            h = next(hash_iter)
            rows_full.append(found.get(h, ""))
        else:
            rows_full.append("(invalid)")

    found_salt = None
    if known_numbers:
        temp_files = []
        for i, known in enumerate(known_numbers, start=1):
            df_copy = pd.DataFrame({"password": rows_full})
            df_copy["subtracted"] = df_copy["password"].apply(lambda p: compute_subtracted_value(p, known, salt_type))
            out_file = TEMP_DIR / f"file_{i}.xlsx"
            df_copy.to_excel(out_file, index=False)
            temp_files.append(out_file)

        try:
            first_df = pd.read_excel(temp_files[0], dtype=str)
            set0 = set(first_df["subtracted"].dropna().astype(str).tolist())
            intersect_set = set0
            for f in temp_files[1:]:
                new_df = pd.read_excel(f, dtype=str)
                current_set = set(new_df["subtracted"].dropna().astype(str).tolist())
                intersect_set = intersect_set.intersection(current_set)
                print(f"Intersection size now: {len(intersect_set)}")
            if len(intersect_set) == 1:
                candidate = next(iter(intersect_set))
                if isinstance(candidate, str) and candidate.endswith(".0"):
                    candidate = candidate[:-2]
                if salt_type == "numeric":
                    try:
                        found_salt = int(candidate)
                        print(f"Numeric salt found: {found_salt}")
                    except Exception:
                        found_salt = None
                else:
                    found_salt = candidate
                    print(f"String salt found: '{found_salt}'")
        except Exception as e:
            print(f"Error during salt intersection: {e}")

    output_df = df.copy()
    col0 = output_df.columns[0]

    if found_salt is None:
        output_df[col0] = rows_full
        salt_to_return = 0
        print("Salt was not found. Returning raw found values (or (invalid)).")
    else:
        if salt_type == "numeric":
            restored = []
            for p in rows_full:
                try:
                    if p in ("", "(invalid)"):
                        restored.append(pd.NA)
                    else:
                        restored.append(int(p) - int(found_salt))
                except Exception:
                    restored.append(pd.NA)
            output_df[col0] = restored
            salt_to_return = found_salt
        else:
            restored = []
            salt_str = str(found_salt)
            len_salt = len(salt_str)
            for p in rows_full:
                try:
                    if p in ("", "(invalid)"):
                        restored.append(pd.NA)
                    elif isinstance(p, str) and p.endswith(salt_str):
                        line_part = p[:-len_salt]
                        if re.fullmatch(r"\d+", line_part):
                            restored.append(int(line_part))
                        else:
                            restored.append(line_part)
                    else:
                        restored.append(pd.NA)
                except Exception:
                    restored.append(pd.NA)
            output_df[col0] = restored
            salt_to_return = found_salt

    remove_path(HASHES_TXT)
    remove_path(OUTPUT_RAW)
    remove_path(TEMP_DIR)

    return output_df, salt_to_return