import socket
import threading
import time
import datetime

SERVER = socket.gethostbyname(socket.gethostname())
# SERVER_DIKA = "172.20.10.6"
# print(sock et.gethostbyaddr("101.255.119.178"))
PORT = 5049
AUTH_PORT = 5048
# PORT_DIKA = 5050

client_list : set[tuple[str, int]] = set()

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
auth = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

auth.bind((SERVER, AUTH_PORT))
server.bind((SERVER, PORT))

PASS = "123464".encode()

def handshake_listener():
    while True:
        password, addr = auth.recvfrom(2048)
        if(password == PASS):
            client_list.add(addr)
            auth.sendto(consya, addr)
        else:
            auth.sendto("pw salah".encode(), addr)

def process_message(msg: bytes, address): 
    if(address in client_list): 
        for addr in client_list:
            if addr == address: continue
            server.sendto(str(address).encode(), addr)
            server.sendto(msg, addr)
    else:
        server.sendto("Please authenticate first!".encode(), addr)


def receive_message():
    while True:
        msg, addr = server.recvfrom(2048)
        print(f"{datetime.datetime.now()} [INCOMING MESSAGE] {addr} {msg.decode()}")
        threading.Thread(target=process_message, args=(msg, addr)).start()
        
        # time.sleep(2000)

        # server.sendto(msg, (SERVER_DIKA, PORT_DIKA))

print(f"{datetime.datetime.now()} [LISTENING] SERVER IS LISTENING...")
threading.Thread(target=handshake_listener).start()
receive_message()

