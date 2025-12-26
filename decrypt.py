from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

def decrypt_key_rsa(private_key_path, encrypted_key_path):
    key = RSA.import_key(open(private_key_path).read())
    cipher_rsa = PKCS1_OAEP.new(key)
    data = open(encrypted_key_path, "rb").read()
    return cipher_rsa.decrypt(data)

def decrypt_dump(private_key_path):
    aes_key = decrypt_key_rsa(private_key_path, "aes_key.enc")
    nonce = open("aes_nonce.bin", "rb").read()
    tag = open("aes_tag.bin", "rb").read()
    ciphertext = open("encrypted_dump.bin", "rb").read()

    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    dump = cipher.decrypt_and_verify(ciphertext, tag)
    open("decrypted_dump.sql", "wb").write(dump)
    print("Расшифровка завершена → decrypted_dump.sql")

if __name__ == "__main__":
    key = input("Введите путь к RSA-приватному ключу: ")
    decrypt_dump(key)
