import socket
from protocol import Diffie_Hellman_Protocol

HOST = '127.0.0.1'
PORT = 8082

sock = socket.socket()
sock.connect((HOST, PORT))
print(f"Подсоединились к порту: {PORT}")
#g-client_public_key
#p-server_public_key

crypt_client = Diffie_Hellman_Protocol()
crypt_client.bunch_of_public_keys()
keys = str(crypt_client.client_public_key)+' '+str(crypt_client.server_public_key)
sock.send(keys.encode())


msg = sock.recv(1024).decode()
if msg == "Доступ разрешен":
    print(msg+"\nTo exit, send \"exit\"")
    server_key_partial = int(sock.recv(1024).decode())
    client_partial_key = crypt_client.generate_partial_key()
    sock.send(str(client_partial_key).encode())  # отправляем частичный ключ клиента (А) серверу
    crypt_client.generate_full_key(server_key_partial)
    while True:
        msg = input(""">>""")
        if msg == 'exit' or msg == 'Exit':
            sock.send(crypt_client.encrypt_message(msg).encode())
            break
        sock.send(crypt_client.encrypt_message(msg).encode())
    sock.close()
else:
    print("Доступ запрещен")
    sock.close()