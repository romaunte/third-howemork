from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog

from crack_functions import run_deanonymization, save_excel_with_first_header
from encrypt_functions import encrypt_dataset


class DeanonApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Деобезличивание данных")
        self.geometry("480x240")

        self.df_result = None
        self.salt = None
        self.input_path = None

        self.label = tk.Label(self, text="Файл не выбран", anchor="w")
        self.label.pack(fill="x", padx=10, pady=(15, 5))

        self.btn_load = tk.Button(self, text="Загрузить файл", command=self.load_file)
        self.btn_load.pack(fill="x", padx=10, pady=5)

        self.btn_run = tk.Button(self, text="Деобезличить", command=self.run_process, state=tk.DISABLED)
        self.btn_run.pack(fill="x", padx=10, pady=5)

        self.btn_encrypt = tk.Button(self, text="Зашифровать", command=self.run_encryption, state=tk.DISABLED)
        self.btn_encrypt.pack(fill="x", padx=10, pady=5)

        self.btn_save = tk.Button(self, text="Сохранить результат", command=self.save_result, state=tk.DISABLED)
        self.btn_save.pack(fill="x", padx=10, pady=5)

    def load_file(self):
        path = filedialog.askopenfilename(title="Выбери Excel-файл", filetypes=[("Excel Files", "*.xlsx")])
        if path:
            self.input_path = Path(path)
            self.label.configure(text=f"Загружен: {self.input_path.name}")
            self.btn_run.configure(state=tk.NORMAL)

    def ask_salt_type(self, title: str) -> str | None:
        salt_types = ["numeric", "alphabetic", "alphanumeric"]
        while True:
            salt_type = simpledialog.askstring(title, "Введите тип соли (numeric/alphabetic/alphanumeric):", parent=self)
            if salt_type is None:
                return None
            salt_type = salt_type.strip().lower()
            if salt_type in salt_types:
                return salt_type
            messagebox.showwarning("Неверный ввод", "Введите одно из значений: numeric, alphabetic или alphanumeric.")

    def run_process(self):
        if self.input_path is None:
            messagebox.showwarning("Ошибка", "Сначала выберите файл.")
            return

        salt_type = self.ask_salt_type("Тип соли")
        if not salt_type:
            return

        mask_length = simpledialog.askinteger(
            "Длина соли/маски",
            "Введите длину маски для соли численного типа или длину соли для остальных типов:",
            parent=self,
            initialvalue=11,
            minvalue=1,
            maxvalue=32,
        )
        if mask_length is None:
            return

        try:
            df, salt = run_deanonymization(self.input_path, salt_type=salt_type, mask_length=mask_length)
            self.df_result = df
            self.salt = salt
            messagebox.showinfo("Успех", f"Деобезличивание завершено!\nСоль: {salt}")
            self.btn_save.configure(state=tk.NORMAL)
            self.btn_encrypt.configure(state=tk.NORMAL)
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def run_encryption(self):
        if self.df_result is None:
            messagebox.showwarning("Ошибка", "Сначала нужно выполнить деобезличивание или загрузить результаты.")
            return

        algorithm = simpledialog.askstring(
            "Выбор алгоритма",
            "Введите алгоритм хеширования (md5/sha1/sha256/sha512):",
            parent=self,
        )
        if algorithm is None:
            return
        algorithm = algorithm.strip().lower()
        if algorithm not in {"md5", "sha1", "sha256", "sha512"}:
            messagebox.showwarning("Неверный алгоритм", "Поддерживаются: md5, sha1, sha256, sha512.")
            return

        salt_type = self.ask_salt_type("Тип соли")
        if not salt_type:
            return

        if salt_type == "numeric":
            salt_val = simpledialog.askinteger("Введите соль", "Введите числовую соль (целое число):", parent=self)
            if salt_val is None:
                return
            salt = int(salt_val)
        else:
            salt_text = simpledialog.askstring("Введите соль", "Введите соль (строка):", parent=self)
            if salt_text is None:
                return
            salt = salt_text.strip()

        try:
            self.df_result = encrypt_dataset(self.df_result, algorithm, salt, salt_type)
            messagebox.showinfo("Готово", f"Шифрование выполнено с помощью {algorithm} и типа соли {salt_type}.")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось зашифровать: {e}")

    def save_result(self):
        if self.df_result is None:
            messagebox.showwarning("Ошибка", "Нет результата для сохранения.")
            return

        save_path = filedialog.asksaveasfilename(
            title="Сохранить результат",
            defaultextension=".xlsx",
            initialfile="cracked.xlsx",
            filetypes=[("Excel Files", "*.xlsx")],
        )
        if save_path:
            save_excel_with_first_header(self.df_result, save_path)
            messagebox.showinfo("Сохранено", f"Файл сохранён: {save_path}")


def main():
    app = DeanonApp()
    app.mainloop()


if __name__ == "__main__":
    main()
