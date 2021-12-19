import random
import socket
from protocol import Diffie_Hellman_Protocol

HOST = '127.0.0.1'
PORT = 8082

sock = socket.socket()
sock.bind((HOST, PORT))
sock.listen(1)
conn, addr = sock.accept()
print(f'Слушаем {PORT} порт...')

def make_keys(conn):
    bunch = conn.recv(2054).decode()
    bunch = bunch.split(' ')
    crypt_server = Diffie_Hellman_Protocol(int(bunch[0]), int(bunch[1]), random.randint(1, 320))
    return crypt_server

def check_access(client_public_key):
    with open('public_keys.txt', 'r') as file:
        flag = False
        for line in file:
            if int(line) == client_public_key:
                flag = True
                break
    return flag

crypt_server = make_keys(conn)

if check_access(crypt_server.client_public_key):
    conn.send("Доступ разрешен".encode())
    server_partial_key = crypt_server.generate_partial_key()
    conn.send(str(server_partial_key).encode())
    client_key_partial = int(conn.recv(1024).decode())
    print(client_key_partial)
    crypt_server.generate_full_key(client_key_partial)
    while True:
        msg = conn.recv(2024).decode()
        print(f'Зашированное сообщение: {msg} \nЗашифрованное сообщение: {crypt_server.decrypt_message(msg)}\n')
        if crypt_server.decrypt_message(msg) == 'Exit' or crypt_server.decrypt_message(msg) == 'exit':
            break
    conn.close()
else:
    conn.close()