import socket
from message import Message
import constant
import threading

SERVER = socket.gethostbyname(socket.gethostname())
PORT = 5000

class CentralServer:
    user_data : dict[str, int] = dict()
    
    def __init__(self) -> None:
        self.dbsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dbsocket.bind((SERVER, PORT))
        threading.Thread(target=self.request_listener, daemon=True).start()
        pass

    def add_user(self, uname: str, password: str):
        self.user_data[uname] = password
        print(f"[NEW USER ADDED] '{uname}'")

    def attempt_login(self, uname: str, password: str) -> tuple[str, str]:
        print(f"uname exist: {uname in self.user_data} pass_data = {self.user_data[uname]} pass = {password}")
        if (uname in self.user_data) and (self.user_data[uname] == password):
            print("EQUAL")
            return (constant.TYPE_SUCCESS_CENTRAL, "User logged in.")
        else:
            print("!EQUAL")
            return (constant.TYPE_FAIL_CENTRAL, "Wrong username or password. Please try again!")
    
    def attempt_register(self, uname: str, password: str) -> tuple[str, str]:
        if uname in self.user_data:
            return (constant.TYPE_FAIL_CENTRAL, f"Username '{uname}' already exist. Pick another username")
        else:
            self.add_user(uname, password)

            return (constant.TYPE_SUCCESS_CENTRAL, "User registration success.")

    def handle_request(self, packet, addr):
        print("CALLED")
        packet = Message.decode(packet)
        print(f"[NEW REQUEST] type:{packet.header}")
        (uname, password) = packet.body.split('|')
        print(password + 'a')
        if(packet.header == constant.TYPE_REGISTER_CENTRAL):
            header, body = self.attempt_register(uname, password)
        elif(packet.header == constant.TYPE_LOGIN_CENTRAL):
            header, body = self.attempt_login(uname, password)
        else: header, body = (constant.TYPE_FAIL_CENTRAL, "Wrong username or password. Please try again!")
        
        response = Message(
            SERVER,
            PORT,
            header,
            body
        ).encode()
        self.dbsocket.sendto(response, addr)

    def request_listener(self):
        print(f"[LISTENING] {self.dbsocket.getsockname()} is listening...")
        while True:
            print("AS")
            packet, addr = self.dbsocket.recvfrom(2048)
            print("AS")
            threading.Thread(target=self.handle_request, args = (packet, addr)).start()                  
    
    @staticmethod
    def export():
        file = open("user.txt")
        db = CentralServer()
        file.readline()
        for line in file:
            data = line.strip().split('|')
            db.user_data[data[0]] = data[1]
        file.close()
        return db
    

    
    def imprt(self):
        file = open("user.txt", "w")
        file.write("uname|pass\n")
        for k, v in self.user_data.items():
            file.write(f"{k}|{v}\n")
        file.close()
        
db = CentralServer.export()
for k,v in db.user_data.items():
    print(k, v)

if(input() == 'QUIT'):
    db.imprt()
