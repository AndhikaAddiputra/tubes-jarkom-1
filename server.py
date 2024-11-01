import socket
import threading
import datetime
import constant
import time
from encrypt import RSA
from message import Message


PASS = "123456".encode()
class Server:
    
    def __init__(self, ip: str, port: int) -> None:
        self.ip = ip
        self.port = port

        # RSA setup
        (self.priv_key, self.pub_key, self.n) = RSA.generate_key()
        # print(self.priv_key, "ASAS", self.n)
        self.rsa = RSA(self.priv_key, self.n)

        # Server initialization
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind((ip, port))

    
    def handle_pub_received(self, body: str) -> tuple[int, int]:
        (exponent, modulus) = body.split('|')
        return (int(exponent), int(modulus))


class Stream(Server):
    
    def __init__(self, room, addr, ip: str, origin_pub: dict[str, int]) -> None:
        super().__init__(ip , 0)
        self.room = room
        self.origin = addr
        self.origin_pub = (origin_pub["exponent"], origin_pub["modulus"])
        self.port = self.server.getsockname()[1]

        threading.Thread(target=self.receive_message, daemon=True).start()

    def receive_message(self):
        while True:
            packet, addr = self.server.recvfrom(4096)
            packet = Message.decode(packet)
            if(addr == self.origin and packet.header == constant.TYPE_DISCONNECT):
                print(f"{self.server.getsockname()} disconnected! bye.")
                # self.send_message(addr, packet.body)
                self.server.close()
                self.room.remove_stream(self)
                break
                
            if addr != self.origin: 
                self.server.sendto("Unauthorized!", addr)
            else:
                self.room : ChatRoom
                packet.body = self.rsa.decrypt(packet.body)
                self.room.broadcast(addr,packet.body, packet.source_username)
                print(f"{datetime.datetime.now()} [INCOMING MESSAGE] {addr} {packet.body}")

    def send_message(self,addr,msg: str, uname: str = "stream"):
        msg = str(self.rsa.encrypt(msg, self.origin_pub))
        packet = Message(
            addr[0],
            addr[1],
            constant.TYPE_MESSAGE,
            uname,
            0,
            msg
        ).encode()

        self.server.sendto(packet, self.origin)

class ChatRoom(Server):
            
    members : list[Stream] = list()
    clients_key: dict[str, dict[str, int]] = dict()
    def __init__(self, ip: str, port: int) -> None:
        super().__init__(ip, port)
        threading.Thread(target=self.handshake_listener, daemon=True).start()
        self.room_identifier = f"|room@{self.ip}:{self.port}"

    def key_handshake(self, messages: Message, origin): # performs public key handshake
        # Store the key
        exponent, modulus = self.handle_pub_received(messages.body)
        self.clients_key[messages.source_username] = {
            "exponent":exponent, 
            "modulus":modulus
        }

        # Send server public key to client
        packet = Message(
            self.server.getsockname()[0], 
            self.server.getsockname()[1],  
            constant.TYPE_RESPONSE_PUB,
            self.room_identifier,
            0,
            f"{self.pub_key}|{self.n}"
        ).encode()
        self.server.sendto(packet, origin)

    def request_handler(self, packet, addr):
        messages = Message.decode(packet)
        if(messages.header == constant.TYPE_REQ_PUB): # Handshake
            self.key_handshake(messages, addr)

        elif(messages.header == constant.TYPE_AUTH): # Authentication
            password = self.rsa.decrypt(messages.body).encode()
            if(password == PASS):
                if addr in [stream.origin for stream in self.members]:
                    print(f"Client {addr} already connected to the room.")
                    return
                stream = Stream(self, addr, self.ip, self.clients_key[messages.source_username])
                packet = Message(
                    self.ip, 
                    self.port, 
                    constant.SERVER_AUTH_SUCCESS,
                    self.room_identifier,
                    0,
                    str(stream.port) + '|' + str(stream.pub_key) + '|' + str(stream.n)
                ).encode()
                self.server.sendto(packet, addr)

                self.members.append(stream)
                print(f"[NEW STREAM] STREAM({stream.origin}) CONNECTED")

            else: # wrong password
                packet = Message(
                    self.ip, 
                    self.port, 
                    constant.SERVER_AUTH_FAIL,
                    self.room_identifier,
                    0, 
                    "Wrong Password"
                ).encode()
                self.server.sendto(packet, addr)
    
    def handshake_listener(self):
        while True:
            packet, addr = self.server.recvfrom(4096)
            threading.Thread(target=self.request_handler, args=(packet, addr), daemon=True).start()

    def broadcast(self, addr, msg, uname): 
        for member in self.members:
            if member.origin == addr: continue
            member.send_message(addr, msg, uname)

    def remove_stream(self, stream: Stream):
        print("ONE STREAM DELETED")
        self.server.sendto(" ".encode(), stream.origin)
        print(stream.origin)
        self.members.remove(stream)
        
if __name__ == "__main__":
    port = int(input("Input port number for server: "))
    room = ChatRoom(socket.gethostbyname(socket.gethostname()),port)
    print(f"[LISTENING] {room.server.getsockname()} is listening...")
    input()
    
