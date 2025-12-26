# vsosh
Проект: Защита экспорта баз данных (AES–RSA)

Файлы:
- secure_export.py - перехват и шифрование экспорта SQLite
- decrypt.py - расшифровка дампа владельцем
- пример_базы.db - тестовая SQLite база

Генерация RSA ключей:
openssl genrsa -out private.pem 2048 && openssl rsa -in private.pem -out public.pem -pubout

Использование:
python secure_export.py пример_базы.db public.pem 

Расшифровка базы:
python decrypt.py private.pem
