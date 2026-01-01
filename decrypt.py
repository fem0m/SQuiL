import zipfile
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

def decrypt_key_rsa(encrypted_key, private_key_path):
    key = RSA.import_key(open(private_key_path).read())
    cipher_rsa = PKCS1_OAEP.new(key)
    return cipher_rsa.decrypt(encrypted_key)

def decrypt_aes(ciphertext, aes_key, nonce, tag):
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def load_from_zip(zip_path):
    with zipfile.ZipFile(zip_path, 'r') as z:
        ciphertext = z.read('encrypted_dump.bin')
        encrypted_key = z.read('aes_key.enc')
        nonce = z.read('aes_nonce.bin')
        tag = z.read('aes_tag.bin')
    return ciphertext, encrypted_key, nonce, tag

def decrypt_container(zip_path, private_key_path):
    ciphertext, encrypted_key, nonce, tag = load_from_zip(zip_path)

    aes_key = decrypt_key_rsa(encrypted_key, private_key_path)

    try:
        plaintext = decrypt_aes(ciphertext, aes_key, nonce, tag)
    except ValueError as e:
        print("Ошибка расшифровки: неверный ключ или повреждённый файл.")
        return

    with open("decrypted_dump.sql", "wb") as f:
        f.write(plaintext)

    print("Расшифровка завершена. Сохранено в decrypted_dump.sql.")

if __name__ == "__main__":
    zip_file = input("Введите путь к secure_container.zip: ")
    private_key = input("Введите путь к RSA-приватному ключу (.pem): ")
    decrypt_container(zip_file, private_key)