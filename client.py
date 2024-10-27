import socket
import threading
import datetime
import constant   
from encrypt import RSA  
from message import Message

# SERVER = "172.20.10.3"
SERVER = socket.gethostbyname(socket.gethostname())
# PORT = 5049
CENTRAL_PORT = 5000
CENTRAL_PUB, CENTRAL_N = RSA.load_pub("ganyang_fufufafa.pub")

class Client:
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSocket.bind((SERVER, 0))
    port = clientSocket.getsockname()[1]
    (priv_key, pub_key, n) = RSA.generate_key()
    rsa = RSA(priv_key, n)
    PORT = clientSocket.getsockname()[1]
    
    # stream
    chatAddress = ("-1", -1)
    chatPub = (0, 0)

    # auth
    username = ""
    password = ""

    # server pub
    room_exponent = 0
    room_modulus = 0

    def handle_pub_received(self, packet_body: str) -> tuple[int, int]:
        exponent, modulus = packet_body.split('|')
        return (int(exponent), int(modulus))
    
    def pub_handshake(self, addr):
        req_packet = Message(
            SERVER,
            self.port,
            constant.TYPE_REQ_PUB,
            self.username,
            0,
            f"{self.pub_key}|{self.n}"
        ).encode()

        self.clientSocket.sendto(req_packet, addr)
        pub_key, address = self.clientSocket.recvfrom(4096)
        if(address == addr):
            pub_key = Message.decode(pub_key)
            self.room_exponent, self.room_modulus = self.handle_pub_received(pub_key.body)

    def handle_server_succes(self, packet_body: str) -> tuple[int, int, int]:
        (port, pub, n) = packet_body.split('|')
        return (int(port), int(pub), int(n))

        
    def connect(self, addr, password: str) -> tuple[bool, str]:
        
        req_packet = Message(
            SERVER,
            self.port,
            constant.TYPE_REQ_PUB,
            self.username,
            0,
            f"{self.pub_key}|{self.n}"
        ).encode()

        self.clientSocket.sendto(req_packet, addr)
        pub_key, address = self.clientSocket.recvfrom(4096)
        if(address == addr):
            pub_key = Message.decode(pub_key)
            self.room_exponent, self.room_modulus = self.handle_pub_received(pub_key.body)
            
        encryted_password = str(self.rsa.encrypt(password, (self.room_exponent, self.room_modulus)))
        packet = Message(SERVER,
                         self.port,
                         constant.TYPE_AUTH,
                         self.username,
                         0,
                        encryted_password).encode()
        
        self.clientSocket.sendto(packet, addr)

        packet, address = self.clientSocket.recvfrom(4096)
        if(address == addr):
            packet = Message.decode(packet)
            if(packet.header == constant.SERVER_AUTH_SUCCESS):
                (prot, pub, n) = self.handle_server_succes(packet.body)
                self.chatPub = (pub, n)
                self.chatAddress = (addr[0], prot)
                print(f"{self.chatAddress} connected!")
                return (True, "")
            else:
                return (False, packet.body)
        else:
            return (False, "Unauthorized!")
        
    def receive_message(self):
        # print("AHLAN")
        while True and self.chatAddress[1] != -1:
            packet, addr = self.clientSocket.recvfrom(4096)
            # print("ANJG")
            # address = (chatIp, chatPort)
            if(addr == self.chatAddress): # authorized
                packet = Message.decode(packet)
                packet.body = self.rsa.decrypt(packet.body)
                print(f"[{packet.source_username}] {packet.body}")
        # print("Bye!")

                    

    def send_message(self, message: str):
        message = str(self.rsa.encrypt(message, self.chatPub))
        if(self.chatAddress[1] != -1):
            packet = Message(self.clientSocket.getsockname()[0], 
                             self.clientSocket.getsockname()[1], 
                             constant.TYPE_MESSAGE, 
                             self.username,
                             0,
                             message).encode()
            
            self.clientSocket.sendto(packet, self.chatAddress)
    
    def disconnect(self): 
        packet = Message(self.clientSocket.getsockname()[0], 
                        self.clientSocket.getsockname()[1], 
                        constant.TYPE_DISCONNECT, 
                        self.username,
                        0,
                        "").encode()
        self.clientSocket.sendto(packet, self.chatAddress)
        self.chatAddress = ("-1", -1)

    def doActionCentral(self, action: str, uname: str, password: str) -> tuple[bool, str]:
        encrypted_password = self.rsa.encrypt(password, (CENTRAL_PUB, CENTRAL_N))
        packet = Message(
            SERVER,
            self.PORT,
            action,
            uname,
            0,
            f"{uname}|{encrypted_password}|0"
        ).encode()
        self.clientSocket.sendto(packet, (SERVER, CENTRAL_PORT))
        print("SENT!")

        addr = ("0", 0)
        while(addr != (SERVER, CENTRAL_PORT)):
            print("WAIT")
            result, addr = self.clientSocket.recvfrom(2048)
        
        result = Message.decode(result)
        print(result.header)
        status = result.header == constant.TYPE_SUCCESS_CENTRAL
        if status:
            self.username = uname
        return (status, result.body)

    def generate_key(self):
        (self.priv_key, self.pub_key, self.n) = self.rsa.generate_key()
        
if __name__ == "__main__":
    client = Client()
    IP = client.clientSocket.getsockname()[0]
    PORT = client.clientSocket.getsockname()[1]

    print(f"Welcome to GanyangFufufa! ({client.clientSocket.getsockname()}). Please choose your desired action below:")
    while True:
        print("1. Register")
        print("2. Login")
        ans = input(': ')
        while(ans != '1' and ans != '2'):
            print("Invalid blog💀")
            ans = input(': ')

        success = False
        while not success:
            uname = input("Username: ")
            password = input("Password: ")
            if(ans == "1"):
                print("c")
                success, msg = client.doActionCentral(constant.TYPE_REGISTER_CENTRAL, uname, password)
                if not success:
                    print("Registration Failed. Reason: " + msg)
            elif(ans == "2"):
                success, msg = client.doActionCentral(constant.TYPE_LOGIN_CENTRAL, uname, password)
                if not success:
                    print("Login Failed. Reason: " + msg)
                    

        while success:
            chatIP = input("Enter the room ip to connect: ")
            if(chatIP == "logout"):
                break
            chatPort = int(input("Enter the room port to connect: "))
            chatPassword = input("Enter the room password to connect: ")

            result = client.connect((chatIP, chatPort), chatPassword)
            if(result[0]):
                threading.Thread(target=client.receive_message, daemon=True).start()
                while True:
                    message = input()
                    if(message == ":q"):
                        break
                    else:
                        client.send_message(message)
                client.disconnect()
            else:
                print("Connection failed because of the reason stated above. You can try again if you wish")
