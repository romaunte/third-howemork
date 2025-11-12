import hashlib
import pandas as pd

def validate_algorithm(algorithm: str) -> callable:
    if not hasattr(hashlib, algorithm):
        raise ValueError(f"Algorithm '{algorithm}' is not supported by hashlib.")
    return getattr(hashlib, algorithm)

def encrypt_dataset(df: pd.DataFrame, algorithm: str, salt, salt_type: str) -> pd.DataFrame:
    print(f"Encrypt launch: algorithm = {algorithm}, salt_type = {salt_type}, salt = {salt}")

    hash_func = validate_algorithm(algorithm)
    lines = df.iloc[:, 0].astype(str).tolist()

    encoded = []
    for pwd in lines:
        if pwd is None or pwd == "":
            encoded.append(pwd)
            continue
        try:
            if salt_type == "numeric":
                combined = str(int(pwd) + int(salt)).encode()
            elif salt_type in ("alphabetic", "alphanumeric"):
                combined = (str(pwd) + str(salt)).encode()
            else:
                combined = str(pwd).encode()

            hashed = hash_func(combined).hexdigest()
            encoded.append(hashed)
        except Exception:
            encoded.append(pwd)

    df = df.copy()
    df[df.columns[0]] = encoded
    print("Encrypting successfully finished.")
    return df