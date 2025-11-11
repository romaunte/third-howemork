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
import itertools
import random
import shutil
import string
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

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

ALPHABETS = {
    "numeric": string.digits,
    "alpha": string.ascii_lowercase,
    "mixed": string.ascii_lowercase + string.digits,
}

# -------------- hashcat helpers ----------------------
def ensure_hashcat(path: str) -> str:
    p = Path(path)
    if p.exists():
        return str(p.resolve())
    resolved = shutil.which(path)
    if resolved is None:
        raise FileNotFoundError(
            f"Не найден '{path}'. Установите hashcat и добавьте в PATH, "
            f"или укажите полный путь в поле 'Hashcat path'."
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
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

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

def load_known_pairs(rows: Iterable[Dict[str, str]], limit: int) -> List[KnownPair]:
    known: List[KnownPair] = []
    for r in rows:
        if len(known) >= limit:
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

# -------------- GUI -----------------------
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

        # Hashcat path
        row = ttk.Frame(frm); row.pack(fill="x", pady=6)
        ttk.Label(row, text="Hashcat path:").pack(side="left")
        self.hc_var = tk.StringVar(value="hashcat")  # можно указать полный путь к hashcat.exe
        ttk.Entry(row, textvariable=self.hc_var, width=50).pack(side="left", padx=6)

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
        ttk.Label(row, text="Маска телефона:").pack(side="left", padx=(12,0))
        self.mask_var = tk.StringVar(value="8?d?d?d?d?d?d?d?d?d?d")
        ttk.Entry(row, textvariable=self.mask_var, width=28).pack(side="left", padx=6)

        # Salt config
        row = ttk.Frame(frm); row.pack(fill="x", pady=6)
        ttk.Label(row, text="Тип соли:").pack(side="left")
        self.salt_type_var = tk.StringVar(value="numeric")
        ttk.Combobox(row, textvariable=self.salt_type_var,
                     values=["numeric","alpha","mixed"], state="readonly", width=10).pack(side="left", padx=6)
        ttk.Label(row, text="Длина соли (min-max):").pack(side="left", padx=(12,0))
        self.salt_min = tk.IntVar(value=1)
        self.salt_max = tk.IntVar(value=4)
        ttk.Spinbox(row, from_=0, to=8, textvariable=self.salt_min, width=4).pack(side="left", padx=3)
        ttk.Spinbox(row, from_=0, to=8, textvariable=self.salt_max, width=4).pack(side="left", padx=3)
        ttk.Label(row, text="Кол-во известных пар (валидация):").pack(side="left", padx=(12,0))
        self.known_n = tk.IntVar(value=5)
        ttk.Spinbox(row, from_=1, to=50, textvariable=self.known_n, width=5).pack(side="left", padx=3)

        # Extra args
        row = ttk.Frame(frm); row.pack(fill="x", pady=6)
        ttk.Label(row, text="Доп. аргументы hashcat (необязательно):").pack(side="left")
        self.extra_args = tk.StringVar(value="--force")
        ttk.Entry(row, textvariable=self.extra_args, width=50).pack(side="left", padx=6)

        # Buttons
        row = ttk.Frame(frm); row.pack(fill="x", pady=10)
        ttk.Button(row, text="Восстановить телефоны (hashcat)", command=self.run_crack).pack(side="left", padx=6)
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
        mask = self.mask_var.get().strip() or "8?d?d?d?d?d?d?d?d?d?d"
        salt_type = self.salt_type_var.get()
        min_len, max_len = int(self.salt_min.get()), int(self.salt_max.get())
        if max_len < min_len:
            messagebox.showerror("Ошибка", "Длина соли: max < min")
            return

        # выбрать путь к hashcat
        try:
            hashcat_path = ensure_hashcat(self.hc_var.get().strip() or "hashcat")
        except Exception as e:
            messagebox.showerror("Hashcat", str(e)); return

        # подготовка данных
        known = load_known_pairs(rows, self.known_n.get())
        if not known:
            messagebox.showerror("Ошибка", "Не удалось найти известные пары (колонка C должна содержать телефоны хотя бы в нескольких строках).")
            return
        all_hashes = load_all_hashes(rows)
        if not all_hashes:
            messagebox.showerror("Ошибка", "Не найдены значения хэшей в колонке A.")
            return

        # генерируем соли
        salts: List[str] = []
        if pattern != "phone":
            alphabet = ALPHABETS[salt_type]
            space = SaltSearchSpace(f"{salt_type}({min_len}-{max_len})", alphabet, min_len, max_len)
            # ВНИМАНИЕ: количество комбинаций растёт экспоненциально.
            # Для лабораторных типичные min/max малы (1-4).
            salts = list(space.generate())
            salts = sorted(set(salts))
            if not salts:
                messagebox.showerror("Ошибка", "Не сгенерировались значения соли.")
                return

        self.log_print(f"Найдено известных пар: {len(known)}; всего хэшей: {len(all_hashes)}; солей: {len(salts)}")
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
            if pattern != "phone":
                write_lines(salts_file, salts)

            extra = self.extra_args.get().strip().split() if self.extra_args.get().strip() else []

            # 1) Валидация на известных парах
            self.log_print(f"Валидация на известных парах: m={m}, a={a_mode}, pattern={pattern}")
            code, cracked_known, proc = run_hashcat(
                hashcat=hashcat_path,
                hash_type=m,
                attack_mode=a_mode,
                hash_file=known_hashes,
                mask=mask,
                salts_file=salts_file if pattern!="phone" else None,
                extra_args=extra,
            )
            # показать вывод
            if proc.stdout: self.log_print(proc.stdout)
            if proc.stderr: self.log_print(proc.stderr)

            if len(cracked_known) < len(known):
                self.log_print(f"Не все известные пары восстановлены ({len(cracked_known)}/{len(known)}). Останавливаюсь.")
                messagebox.showwarning("Валидация не пройдена",
                                       f"Восстановлено {len(cracked_known)} из {len(known)} известных телефонов. "
                                       f"Уточните маску/соль/алгоритм.")
                return
            self.log_print("Валидация пройдена. Запускаю на всём наборе…")

            # 2) Полный набор
            code, cracked_all, proc2 = run_hashcat(
                hashcat=hashcat_path,
                hash_type=m,
                attack_mode=a_mode,
                hash_file=all_hashes_file,
                mask=mask,
                salts_file=salts_file if pattern!="phone" else None,
                extra_args=extra,
            )
            if proc2.stdout: self.log_print(proc2.stdout)
            if proc2.stderr: self.log_print(proc2.stderr)

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
