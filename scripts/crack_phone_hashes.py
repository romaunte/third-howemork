#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GUI-инструмент лабораторной: восстановление телефонов из хэшей через hashcat.
- Читает XLSX (A=hash, C=phone для валидации на нескольких строках)
- Выбор алгоритма (MD5/SHA1/SHA256/SHA512), типа соли (цифры/буквы/смешанная), длины соли, паттерна (salt+phone/phone+salt/phone)
- Запускает hashcat, сначала валидирует на известных парах (C), затем брутит весь столбец A
- Сохраняет CSV с восстановленными телефонами (столбец C заменяется на найденные значения)
- Исправлено ограничение "работает только из папки hashcat": hashcat запускается с cwd=его каталогу и PATH дополняется
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import shutil
import string
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

# --- GUI (tkinter)
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except Exception:
    tk = None  # если нет GUI-окружения

NAMESPACE = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"

# ---------------- XLSX minimal reader ----------------
def _fromstring(data: bytes):
    from xml.etree import ElementTree as ET
    return ET.fromstring(data)

def iter_rows(path: Path) -> Iterator[Dict[str, str]]:
    with zipfile.ZipFile(path) as zf:
        shared_strings = []
        try:
            shared_xml = zf.read("xl/sharedStrings.xml")
            root = _fromstring(shared_xml)
            for si in root:
                t = si.find(f".//{NAMESPACE}t")
                shared_strings.append(t.text if t is not None else "")
        except KeyError:
            shared_strings = []

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

# -------------- salt search space --------------------
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

    def count(self) -> int:
        chars = len(self.alphabet)
        total = 0
        for length in range(self.min_length, self.max_length + 1):
            if length == 0:
                total += 1
            else:
                total += chars ** length
        return total

ALPHABETS = {
    "numeric": string.digits,
    "alpha": string.ascii_lowercase,
    "mixed": string.ascii_lowercase + string.digits,
}

# -------------- hashcat helpers ----------------------
DEFAULT_HASHCAT_PATH = r"C:\\Program Files\\hashcat-7.1.2"
MAX_AUTO_SALT_LENGTH = 10
AUTO_SALT_COMBO_LIMIT = 1_000_000


def ensure_hashcat(path: str) -> str:
    p = Path(path)
    if p.exists():
        if p.is_dir():
            candidates = [p / "hashcat.exe", p / "hashcat"]
            for cand in candidates:
                if cand.exists():
                    return str(cand.resolve())
        else:
            return str(p.resolve())
    resolved = shutil.which(path)
    if resolved is None:
        raise FileNotFoundError(
            f"Не найден '{path}'. Установите hashcat и добавьте в PATH, "
            f"или укажите полный путь к hashcat."
        )
    return resolved

def _prepare_hashcat_cwd_and_env(hashcat_path: str) -> Tuple[str, Dict[str, str]]:
    from os import environ
    exe = Path(hashcat_path).resolve()
    if not exe.exists():
        raise FileNotFoundError(f"hashcat не найден по пути {hashcat_path}")
    hc_dir = str(exe.parent)
    env = dict(environ)
    sep = ";" if sys.platform == "win32" else ":"
    env["PATH"] = hc_dir + (sep + env.get("PATH", ""))  # как будто запустили из его папки
    return hc_dir, env

def write_lines(path: Path, lines: Iterable[str]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for line in lines:
            fh.write(f"{line}\n")

def parse_outfile(path: Path) -> Dict[str, str]:
    cracked: Dict[str, str] = {}
    if not path.exists():
        return cracked
    for line in path.read_text(encoding="utf-8").splitlines():
        if ":" not in line:
            continue
        h, plain = line.split(":", 1)
        cracked[h.strip()] = plain.strip()
    return cracked

PATTERN_TO_ATTACK_MODE = {
    "phone": 3,        # -a 3: mask only
    "salt+phone": 6,   # -a 6: wordlist (salts) + mask
    "phone+salt": 7,   # -a 7: mask + wordlist (salts)
}

HASH_NAME_TO_M = {
    "MD5": 0,
    "SHA1": 100,
    "SHA256": 1400,
    "SHA512": 1700,
}

def run_hashcat(*, hashcat: str, hash_type: int, attack_mode: int,
                hash_file: Path, mask: str, salts_file: Optional[Path],
                extra_args: Sequence[str]) -> Tuple[int, Dict[str, str], subprocess.CompletedProcess[str]]:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        outfile = tmp / "hashcat.out"
        potfile = tmp / "hashcat.pot"

        cmd = [
            hashcat,
            "-m", str(hash_type),
            "-a", str(attack_mode),
            "--potfile-path", str(potfile),
            "--outfile", str(outfile),
            "--outfile-format", "2",   # hash:plain
            str(hash_file),
        ]
        if attack_mode == 6:
            if not salts_file:
                raise ValueError("Для паттерна salt+phone нужен файл солей")
            cmd.append(str(salts_file))
            cmd.append(mask)
        elif attack_mode == 7:
            if not salts_file:
                raise ValueError("Для паттерна phone+salt нужен файл солей")
            cmd.append(mask)
            cmd.append(str(salts_file))
        else:
            cmd.append(mask)
        cmd.extend(extra_args)

        cwd, env = _prepare_hashcat_cwd_and_env(hashcat)
        proc = subprocess.run(cmd, text=True, capture_output=True, check=False, cwd=cwd, env=env)
        cracked = parse_outfile(outfile)
        return proc.returncode, cracked, proc

# -------------- business logic -----------------------
@dataclass
class KnownPair:
    hash_value: str
    phone: str

def load_known_pairs(rows: Iterable[Dict[str, str]], limit: Optional[int]) -> List[KnownPair]:
    known: List[KnownPair] = []
    for r in rows:
        if limit is not None and len(known) >= limit:
            break
        h = r.get("A")
        p = r.get("C")
        if h and p:
            known.append(KnownPair(h, p))
    return known

def load_all_hashes(rows: Iterable[Dict[str, str]]) -> List[str]:
    out: List[str] = []
    for r in rows:
        h = r.get("A")
        if h:
            out.append(h)
    return out

def col_letters_to_index(col: str) -> int:
    idx = 0
    for ch in col:
        idx = idx * 26 + (ord(ch.upper()) - ord("A") + 1)
    return idx

def index_to_letters(i: int) -> str:
    s = ""
    x = i
    while x:
        x, rem = divmod(x - 1, 26)
        s = chr(ord("A") + rem) + s
    return s

def max_col_in_rows(rows: List[Dict[str,str]]) -> int:
    m = 0
    for r in rows:
        for k in r.keys():
            try:
                i = col_letters_to_index(k)
                if i > m: m = i
            except Exception:
                pass
    return m


def count_known_pairs_in_column(rows: List[Dict[str, str]], column: str = "C") -> int:
    count = 0
    started = False
    for r in rows:
        val = r.get(column)
        if val:
            count += 1
            started = True
        elif started:
            break
    return count


def _hash_function(name: str):
    mapping = {
        "MD5": hashlib.md5,
        "SHA1": hashlib.sha1,
        "SHA256": hashlib.sha256,
        "SHA512": hashlib.sha512,
    }
    return mapping[name]


def _salt_length_from_plain(plain: str, *, pattern: str, expected_phone: str) -> Optional[int]:
    if pattern == "salt+phone":
        if plain.endswith(expected_phone):
            return len(plain) - len(expected_phone)
        return None
    if pattern == "phone+salt":
        if plain.startswith(expected_phone):
            return len(plain) - len(expected_phone)
        return None
    if pattern == "phone":
        return 0 if plain == expected_phone else None
    return None


def _plain_to_phone(plain: str, *, pattern: str, salt_length: int) -> Optional[str]:
    if pattern == "salt+phone":
        if salt_length == 0:
            return plain
        if len(plain) >= salt_length:
            return plain[salt_length:]
        return None
    if pattern == "phone+salt":
        if salt_length == 0:
            return plain
        if len(plain) >= salt_length:
            return plain[:-salt_length] if salt_length else plain
        return None
    if pattern == "phone":
        return plain
    return None


def detect_salt_length_via_hashcat(*,
                                   known_pairs: Sequence[KnownPair],
                                   alphabet: Sequence[str],
                                   hashcat_path: str,
                                   hash_type: int,
                                   attack_mode: int,
                                   pattern: str,
                                   log: Optional[Callable[..., None]] = None) -> int:
    if not known_pairs:
        raise ValueError("Нет известных пар для определения длины соли")

    if pattern == "phone":
        return 0

    def emit(*parts: object) -> None:
        if log is not None:
            log(*parts)

    alphabet_seq = list(alphabet)
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        known_hashes = tmp / "known.hashes"
        write_lines(known_hashes, [kp.hash_value for kp in known_pairs])

        for length in range(0, MAX_AUTO_SALT_LENGTH + 1):
            space = SaltSearchSpace(f"len={length}", alphabet_seq, length, length)
            combo_count = space.count()
            if combo_count == 0:
                continue
            if combo_count > AUTO_SALT_COMBO_LIMIT:
                emit(f"Пропускаю длину соли {length}: комбинаций {combo_count} > {AUTO_SALT_COMBO_LIMIT}")
                continue

            emit(f"Пробую определить длину соли {length} (комбинаций: {combo_count})…")
            salts_file = tmp / "salts.txt"
            write_lines(salts_file, space.generate())
            _code, cracked, proc = run_hashcat(
                hashcat=hashcat_path,
                hash_type=hash_type,
                attack_mode=attack_mode,
                hash_file=known_hashes,
                mask=DEFAULT_PHONE_MASK,
                salts_file=salts_file if pattern != "phone" else None,
                extra_args=(),
            )
            if proc.stdout:
                emit(proc.stdout)
            if proc.stderr:
                emit(proc.stderr)
            matched_lengths = []
            for kp in known_pairs:
                plain = cracked.get(kp.hash_value)
                if not plain:
                    continue
                detected = _salt_length_from_plain(plain, pattern=pattern, expected_phone=kp.phone)
                if detected is not None:
                    matched_lengths.append(detected)
            if not matched_lengths:
                emit(
                    f"Длина {length} не подошла: ни одна пара не была восстановлена корректно "
                    f"(известных пар: {len(known_pairs)})."
                )
                continue

            unique_lengths = set(matched_lengths)
            if len(unique_lengths) == 1 and length in unique_lengths:
                emit(
                    f"hashcat восстановил {len(matched_lengths)} известных пар при длине соли {length}."
                )
                return length

            emit(
                f"Длина {length} не подошла (совпадений: {len(matched_lengths)}, "
                f"обнаруженные длины: {sorted(unique_lengths)})."
            )

    raise ValueError("Не удалось автоматически определить длину соли в диапазоне 0-10.")


def hash_phone_value(phone: str, *, salt: str, pattern: str, hash_name: str) -> str:
    hfunc = _hash_function(hash_name)
    if pattern == "salt+phone":
        data = salt + phone
    elif pattern == "phone+salt":
        data = phone + salt
    else:
        data = phone
    return hfunc(data.encode("utf-8")).hexdigest()

# -------------- GUI -----------------------
DEFAULT_PHONE_MASK = "8?d?d?d?d?d?d?d?d?d?d"


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Hashcat деобезличивание (восстановление телефонов)")
        root.geometry("760x520")
        frm = ttk.Frame(root, padding=10); frm.pack(fill="both", expand=True)

        # File
        row = ttk.Frame(frm); row.pack(fill="x", pady=6)
        ttk.Label(row, text="XLSX файл:").pack(side="left")
        self.file_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.file_var, width=70).pack(side="left", padx=6)
        ttk.Button(row, text="Обзор…", command=self.browse).pack(side="left")

        # Algorithm / pattern / mask
        row = ttk.Frame(frm); row.pack(fill="x", pady=6)
        ttk.Label(row, text="Алгоритм:").pack(side="left")
        self.alg_var = tk.StringVar(value="SHA256")
        ttk.Combobox(row, textvariable=self.alg_var,
                     values=["MD5","SHA1","SHA256","SHA512"], state="readonly", width=10).pack(side="left", padx=6)
        ttk.Label(row, text="Паттерн:").pack(side="left", padx=(12,0))
        self.pattern_var = tk.StringVar(value="salt+phone")
        ttk.Combobox(row, textvariable=self.pattern_var,
                     values=["salt+phone","phone+salt","phone"], state="readonly", width=12).pack(side="left", padx=6)

        # Salt config
        row = ttk.Frame(frm); row.pack(fill="x", pady=6)
        ttk.Label(row, text="Тип соли:").pack(side="left")
        self.salt_type_var = tk.StringVar(value="numeric")
        ttk.Combobox(row, textvariable=self.salt_type_var,
                     values=["numeric","alpha","mixed"], state="readonly", width=10).pack(side="left", padx=6)

        # Buttons
        row = ttk.Frame(frm); row.pack(fill="x", pady=10)
        ttk.Button(row, text="Восстановить телефоны (hashcat)", command=self.run_crack).pack(side="left", padx=6)
        ttk.Button(row, text="Зашифровать телефоны", command=self.run_encrypt).pack(side="left", padx=6)
        ttk.Button(row, text="Выход", command=root.destroy).pack(side="right", padx=6)

        # Log
        row = ttk.Frame(frm); row.pack(fill="both", expand=True)
        ttk.Label(row, text="Лог:").pack(anchor="w")
        self.log = tk.Text(row, height=14, wrap="word"); self.log.pack(fill="both", expand=True)

    def log_print(self, *parts):
        self.log.insert("end", " ".join(str(p) for p in parts) + "\n")
        self.log.see("end")

    def browse(self):
        p = filedialog.askopenfilename(filetypes=[("Excel files","*.xlsx")])
        if p: self.file_var.set(p)

    def run_crack(self):
        xlsx = self.file_var.get().strip()
        if not xlsx:
            messagebox.showerror("Ошибка", "Выберите XLSX файл.")
            return
        try:
            rows = list(iter_rows(Path(xlsx)))
        except Exception as e:
            messagebox.showerror("Ошибка чтения XLSX", str(e))
            return
        if not rows:
            messagebox.showerror("Ошибка", "В книге не найдено строк.")
            return

        alg = self.alg_var.get()
        m = HASH_NAME_TO_M[alg]
        pattern = self.pattern_var.get()
        a_mode = PATTERN_TO_ATTACK_MODE[pattern]
        salt_type = self.salt_type_var.get()

        # выбрать путь к hashcat
        try:
            try:
                hashcat_path = ensure_hashcat(DEFAULT_HASHCAT_PATH)
            except FileNotFoundError:
                hashcat_path = ensure_hashcat("hashcat")
        except Exception as e:
            messagebox.showerror("Hashcat", str(e)); return

        # подготовка данных
        known_limit = count_known_pairs_in_column(rows)
        known = load_known_pairs(rows, known_limit if known_limit else None)
        if not known:
            messagebox.showerror("Ошибка", "Не удалось найти известные пары (колонка C должна содержать телефоны хотя бы в нескольких строках).")
            return
        all_hashes = load_all_hashes(rows)
        if not all_hashes:
            messagebox.showerror("Ошибка", "Не найдены значения хэшей в колонке A.")
            return

        # генерируем соли
        salt_space: Optional[SaltSearchSpace] = None
        salt_count = 0
        if pattern != "phone":
            alphabet = ALPHABETS[salt_type]
            try:
                detected_length = detect_salt_length_via_hashcat(
                    known_pairs=known,
                    alphabet=alphabet,
                    hashcat_path=hashcat_path,
                    hash_type=m,
                    attack_mode=a_mode,
                    pattern=pattern,
                    log=self.log_print,
                )
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось определить длину соли автоматически: {e}")
                return
            salt_space = SaltSearchSpace(f"{salt_type}(len={detected_length})", alphabet, detected_length, detected_length)
            salt_count = salt_space.count()

        self.log_print(f"Найдено известных пар: {len(known)}; всего хэшей: {len(all_hashes)}; солей: {salt_count}")
        if salt_space is not None:
            self.log_print(f"Длина соли (авто): {salt_space.min_length}")
        out_csv = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")], title="Сохранить результат как")
        if not out_csv:
            return

        # временные файлы
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            known_hashes = tmp / "known.hashes"
            all_hashes_file = tmp / "all.hashes"
            salts_file = tmp / "salts.txt"

            write_lines(known_hashes, [kp.hash_value for kp in known])
            write_lines(all_hashes_file, all_hashes)
            if salt_space is not None:
                write_lines(salts_file, salt_space.generate())

            # 1) Валидация на известных парах
            self.log_print(f"Валидация на известных парах: m={m}, a={a_mode}, pattern={pattern}")
            code, cracked_known_raw, proc = run_hashcat(
                hashcat=hashcat_path,
                hash_type=m,
                attack_mode=a_mode,
                hash_file=known_hashes,
                mask=DEFAULT_PHONE_MASK,
                salts_file=salts_file if pattern!="phone" else None,
                extra_args=(),
            )
            # показать вывод
            if proc.stdout: self.log_print(proc.stdout)
            if proc.stderr: self.log_print(proc.stderr)

            cracked_known = {}
            for h, plain in cracked_known_raw.items():
                phone_value = _plain_to_phone(plain, pattern=pattern, salt_length=salt_space.min_length if salt_space else 0)
                if phone_value is not None:
                    cracked_known[h] = phone_value

            if len(cracked_known) < len(known):
                self.log_print(
                    f"Не все известные пары восстановлены ({len(cracked_known)}/{len(known)}). Останавливаюсь."
                )
                messagebox.showwarning(
                    "Валидация не пройдена",
                    f"Восстановлено {len(cracked_known)} из {len(known)} известных телефонов. "
                    f"Уточните маску/соль/алгоритм."
                )
                return

            mismatched = [kp for kp in known if cracked_known.get(kp.hash_value) != kp.phone]
            if mismatched:
                self.log_print(
                    "Найдены несовпадения между восстановленными телефонами и известными парами. Останавливаюсь."
                )
                messagebox.showerror(
                    "Валидация не пройдена",
                    "Полученные телефоны не совпадают с известными значениями. Проверьте входные данные."
                )
                return
            self.log_print("Валидация пройдена. Запускаю на всём наборе…")

            # 2) Полный набор
            code, cracked_all_raw, proc2 = run_hashcat(
                hashcat=hashcat_path,
                hash_type=m,
                attack_mode=a_mode,
                hash_file=all_hashes_file,
                mask=DEFAULT_PHONE_MASK,
                salts_file=salts_file if pattern!="phone" else None,
                extra_args=(),
            )
            if proc2.stdout: self.log_print(proc2.stdout)
            if proc2.stderr: self.log_print(proc2.stderr)

        cracked_all: Dict[str, str] = {}
        for h, plain in cracked_all_raw.items():
            phone_value = _plain_to_phone(plain, pattern=pattern, salt_length=salt_space.min_length if salt_space else 0)
            if phone_value is not None:
                cracked_all[h] = phone_value

        # собрать CSV: те же колонки, но колонку C заполняем восстановленными телефонами
        max_col = max_col_in_rows(rows)
        # строим заголовки A..N
        headers = [index_to_letters(i) for i in range(1, max_col+1)]
        # Если хотим явно обозначить, что C — восстановлена:
        # заменим имя C на C_RECOVERED
        headers = [("C_RECOVERED" if h == "C" else h) for h in headers]

        recovered_count = 0
        import csv
        with open(out_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(headers)
            for r in rows:
                row_out = []
                h = r.get("A")
                phone = None
                if h and h in cracked_all:
                    phone = cracked_all[h]
                    recovered_count += 1
                for i in range(1, max_col+1):
                    col = index_to_letters(i)
                    if col == "C":
                        row_out.append(phone if phone is not None else "UNKNOWN")
                    else:
                        row_out.append(r.get(col, ""))
                w.writerow(row_out)

        self.log_print(f"Готово. Восстановлено {recovered_count} из {len(all_hashes)}. Результат: {out_csv}")
        messagebox.showinfo("Готово", f"Восстановлено {recovered_count} из {len(all_hashes)} телефонов.\nФайл: {out_csv}")

    def run_encrypt(self):
        xlsx = self.file_var.get().strip()
        if not xlsx:
            messagebox.showerror("Ошибка", "Выберите XLSX файл.")
            return
        try:
            rows = list(iter_rows(Path(xlsx)))
        except Exception as e:
            messagebox.showerror("Ошибка чтения XLSX", str(e))
            return
        if not rows:
            messagebox.showerror("Ошибка", "В книге не найдено строк.")
            return

        alg = self.alg_var.get()
        pattern = self.pattern_var.get()

        out_csv = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")], title="Сохранить результат как")
        if not out_csv:
            return

        phones_present = any(r.get("C") for r in rows)
        if not phones_present:
            messagebox.showerror("Ошибка", "В колонке C нет телефонов для шифрования.")
            return

        if pattern != "phone":
            missing_salt = any(r.get("C") and not r.get("B") for r in rows)
            if missing_salt:
                messagebox.showerror("Ошибка", "Для шифрования с солью необходимо указать соль в колонке B для каждой строки с телефоном.")
                return

        max_col = max_col_in_rows(rows)
        headers = [index_to_letters(i) for i in range(1, max_col+1)]
        headers = [("A_HASHED" if h == "A" else h) for h in headers]

        hashed_count = 0
        import csv
        with open(out_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(headers)
            for r in rows:
                phone = r.get("C")
                salt = r.get("B", "")
                hashed_value = r.get("A", "")
                if phone:
                    if pattern == "phone":
                        salt = ""
                    hashed_value = hash_phone_value(phone, salt=salt, pattern=pattern, hash_name=alg)
                    hashed_count += 1
                row_out: List[str] = []
                for i in range(1, max_col+1):
                    col = index_to_letters(i)
                    if col == "A":
                        row_out.append(hashed_value if phone else r.get(col, ""))
                    else:
                        row_out.append(r.get(col, ""))
                w.writerow(row_out)

        self.log_print(f"Файл зашифрован. Строк обработано: {hashed_count}. Результат: {out_csv}")
        messagebox.showinfo("Готово", f"Создан файл с хэшами. Строк обработано: {hashed_count}.\nФайл: {out_csv}")

# -------------- entrypoints -----------------
def run_gui() -> int:
    if tk is None:
        print("Tkinter недоступен в этой среде.")
        return 1
    root = tk.Tk()
    App(root)
    root.mainloop()
    return 0

def main(argv: Optional[Sequence[str]] = None) -> int:
    # Если запускают с аргументами — дадим простой тест hashcat; без аргументов — GUI
    parser = argparse.ArgumentParser(description="GUI для hashcat-восстановления телефонов из XLSX")
    parser.add_argument("--hashcat", default=None, help="Путь к hashcat (по умолчанию ищется в PATH)")
    parser.add_argument("--test-hashcat", action="store_true", help="Запустить 'hashcat --help' из любой папки (проверка окружения)")
    args = parser.parse_args(argv)

    if args.test_hashcat:
        path = args.hashcat or "hashcat"
        try:
            hc = ensure_hashcat(path)
            cwd, env = _prepare_hashcat_cwd_and_env(hc)
            proc = subprocess.run([hc, "--help"], text=True, capture_output=True, cwd=cwd, env=env)
            print(proc.stdout[:1200])
            if proc.returncode != 0:
                print(proc.stderr)
            return proc.returncode
        except Exception as e:
            print("Ошибка проверки hashcat:", e)
            return 2
    else:
        return run_gui()

if __name__ == "__main__":
    sys.exit(main())
