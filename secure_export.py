import sqlite3
import zipfile
import io
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

def export_database_to_memory(db_path):
    con = sqlite3.connect(db_path)
    dump = '\n'.join(con.iterdump()).encode()
    con.close()
    return dump

def encrypt_aes(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, tag, ciphertext

def encrypt_key_rsa(aes_key, public_key_path):
    key = RSA.import_key(open(public_key_path).read())
    cipher_rsa = PKCS1_OAEP.new(key)
    return cipher_rsa.encrypt(aes_key)

def main():
    db_path = input("Введите путь к базе данных SQLite: ")
    public_key_path = input("Введите путь к RSA-открытому ключу: ")

    dump = export_database_to_memory(db_path)

    aes_key = get_random_bytes(32)
    nonce, tag, ciphertext = encrypt_aes(dump, aes_key)
    encrypted_key = encrypt_key_rsa(aes_key, public_key_path)

    with zipfile.ZipFile("secure_container.zip", "w") as zipf:
        zipf.writestr("encrypted_dump.bin", ciphertext)
        zipf.writestr("aes_key.enc", encrypted_key)
        zipf.writestr("aes_nonce.bin", nonce)
        zipf.writestr("aes_tag.bin", tag)

    print("Экспорт завершён. Создан secure_container.zip.")

if __name__ == "__main__":
    main()