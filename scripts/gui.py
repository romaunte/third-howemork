import sys
from pathlib import Path
from crack_functions import run_deanonymization, save_excel_with_first_header
from encrypt_functions import encrypt_dataset
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton,
    QFileDialog, QMessageBox, QLabel, QInputDialog
)

class DeanonApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Деобезличивание данных")
        self.resize(480, 240)

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.label = QLabel("Файл не выбран")
        self.layout.addWidget(self.label)

        self.btn_load = QPushButton("Загрузить файл")
        self.btn_load.clicked.connect(self.load_file)
        self.layout.addWidget(self.btn_load)

        self.btn_run = QPushButton("Деобезличить")
        self.btn_run.clicked.connect(self.run_process)
        self.btn_run.setEnabled(False)
        self.layout.addWidget(self.btn_run)

        self.btn_encrypt = QPushButton("Зашифровать")
        self.btn_encrypt.clicked.connect(self.run_encryption)
        self.btn_encrypt.setEnabled(False)
        self.layout.addWidget(self.btn_encrypt)

        self.btn_save = QPushButton("Сохранить результат")
        self.btn_save.clicked.connect(self.save_result)
        self.btn_save.setEnabled(False)
        self.layout.addWidget(self.btn_save)

        self.df_result = None
        self.salt = None
        self.input_path = None

    def load_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выбери Excel-файл", "", "Excel Files (*.xlsx)")
        if path:
            self.input_path = Path(path)
            self.label.setText(f"Загружен: {self.input_path.name}")
            self.btn_run.setEnabled(True)

    def run_process(self):
        if self.input_path is None:
            QMessageBox.warning(self, "Ошибка", "Сначала выберите файл.")
            return

        salt_types = ["numeric", "alphabetic", "alphanumeric"]
        salt_type, ok = QInputDialog.getItem(self, "Тип соли", "Выберите тип соли для поиска:", salt_types, 0, False)
        if not ok or not salt_type:
            return

        mask_length, ok_len = QInputDialog.getInt(self,
         "Длина соли/маски", "Введите длину маски для соли численного типа или длину соли для остальных типов:", 11, 1, 32, 1)
        if not ok_len:
            return

        try:
            df, salt = run_deanonymization(self.input_path, salt_type=salt_type, mask_length=mask_length)
            self.df_result = df
            self.salt = salt
            QMessageBox.information(self, "Успех", f"Деобезличивание завершено!\nСоль: {salt}")
            self.btn_save.setEnabled(True)
            self.btn_encrypt.setEnabled(True)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def run_encryption(self):
        if self.df_result is None:
            QMessageBox.warning(self, "Ошибка", "Сначала нужно выполнить деобезличивание или загрузить результаты.")
            return

        algorithms = ["md5", "sha1", "sha256", "sha512"]
        algorithm, ok = QInputDialog.getItem(self, "Выбор алгоритма",
                                             "Выберите алгоритм хеширования:",
                                             algorithms, 0, False)
        if not ok or not algorithm:
            return

        salt_types = ["numeric", "alphabetic", "alphanumeric"]
        salt_type, ok = QInputDialog.getItem(self, "Тип соли", "Выберите тип соли:", salt_types, 0, False)
        if not ok or not salt_type:
            return

        if salt_type == "numeric":
            salt_val, ok = QInputDialog.getInt(self, "Введите соль", "Введите числовую соль (целое число):")
            if not ok:
                return
            salt = int(salt_val)
        else:
            salt_text, ok = QInputDialog.getText(self, "Введите соль", "Введите соль (строка):")
            if not ok:
                return
            salt = salt_text.strip()

        try:
            self.df_result = encrypt_dataset(self.df_result, algorithm, salt, salt_type)
            QMessageBox.information(self, "Готово", f"Шифрование выполнено с помощью {algorithm} и типа соли {salt_type}.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось зашифровать: {e}")

    def save_result(self):
        if self.df_result is None:
            QMessageBox.warning(self, "Ошибка", "Нет результата для сохранения.")
            return

        save_path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить результат", "cracked.xlsx", "Excel Files (*.xlsx)")
        if save_path:
            save_excel_with_first_header(self.df_result, save_path)
            QMessageBox.information(self, "Сохранено", f"Файл сохранён: {save_path}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DeanonApp()
    window.show()
    sys.exit(app.exec_())