import socket
import threading
import datetime
import time
import constant     
from message import Message

# SERVER = "172.20.10.3"
SERVER = socket.gethostbyname(socket.gethostname())
PORT = 5049
CENTRAL_PORT = 5000



class Client:
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSocket.bind((SERVER, 0))
    PORT = clientSocket.getsockname()[1]
    chatAddress = ("-1", -1)

    def connect(self, addr, password: str) -> tuple[bool, str]:
        packet = Message(self.clientSocket.getsockname()[0],
                         self.clientSocket.getsockname()[1],
                         constant.TYPE_AUTH,
                        password).encode()
        
        self.clientSocket.sendto(packet, addr)

        packet, address = self.clientSocket.recvfrom(2048)
        if(address == addr):
            packet = Message.decode(packet)
            if(packet.header == constant.SERVER_AUTH_SUCCESS):
                self.chatAddress = (addr[0], int(packet.body))
                print(f"{self.chatAddress} connected!")
                return (True, "")
            else:
                return (False, packet.body)
        else:
            return (False, "Unauthorized!")
        
    def receive_message(self):
        # print("AHLAN")
        while True and self.chatAddress[1] != -1:
            packet, addr = self.clientSocket.recvfrom(2048)
            # print("ANJG")
            # address = (chatIp, chatPort)
            if(addr == self.chatAddress): # authorized
                packet = Message.decode(packet)
                print(f"[{packet.source_ip}:{packet.source_port}] {packet.body}")
        # print("Bye!")

                    

    def send_message(self, message: str):
        if(self.chatAddress[1] != -1):
            packet = Message(self.clientSocket.getsockname()[0], 
                             self.clientSocket.getsockname()[1], 
                             constant.TYPE_MESSAGE, 
                             message).encode()
            
            self.clientSocket.sendto(packet, self.chatAddress)
    
    def disconnect(self): 
        packet = Message(self.clientSocket.getsockname()[0], 
                        self.clientSocket.getsockname()[1], 
                        constant.TYPE_DISCONNECT, 
                        "").encode()
        self.clientSocket.sendto(packet, self.chatAddress)
        self.chatAddress = ("-1", -1)

    def doActionCentral(self, action: str, uname: str, password: str) -> tuple[bool, str]:
        password = hash(password)
        packet = Message(
            SERVER,
            PORT,
            action,
            f"{uname}|{password}"
        ).encode()


        self.clientSocket.sendto(packet, (SERVER, CENTRAL_PORT))
        print("SENT!")
        addr = ("0", 0)
        while(addr != (SERVER, CENTRAL_PORT)):
            print("WAIT")
            result, addr = self.clientSocket.recvfrom(2048)
        
        result = Message.decode(result)
        print(result.header)
        return (result.header == constant.TYPE_SUCCESS_CENTRAL, result.body)

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
