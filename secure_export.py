import sqlite3
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

def export_sqlite(db_path):
    conn = sqlite3.connect(db_path)
    dump = "\n".join(conn.iterdump())
    conn.close()
    return dump.encode("utf-8")

def encrypt_aes(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, tag, ciphertext

def encrypt_key_rsa(aes_key, public_key_path):
    key = RSA.import_key(open(public_key_path).read())
    cipher_rsa = PKCS1_OAEP.new(key)
    return cipher_rsa.encrypt(aes_key)

def secure_export(db_path, public_key_path):
    dump = export_sqlite(db_path)
    aes_key = get_random_bytes(32)
    nonce, tag, ciphertext = encrypt_aes(dump, aes_key)
    encrypted_key = encrypt_key_rsa(aes_key, public_key_path)

    open("encrypted_dump.bin", "wb").write(ciphertext)
    open("aes_key.enc", "wb").write(encrypted_key)
    open("aes_nonce.bin", "wb").write(nonce)
    open("aes_tag.bin", "wb").write(tag)

    print("Экспорт завершён. Получены файлы: encrypted_dump.bin, aes_key.enc")

if __name__ == "__main__":
    db = input("Введите путь к базе данных SQLite: ")
    key = input("Введите путь к RSA-открытому ключу: ")
    secure_export(db, key)
