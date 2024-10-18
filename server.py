import socket
import threading
import datetime
import constant
import time
from message import Message


PASS = "123456".encode()
class Server:
    
    def __init__(self, ip: str, port: int) -> None:
        self.ip = ip
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind((ip, port))

class Stream(Server):
    
    def __init__(self, room, addr, ip: str) -> None:
        super().__init__(ip , 0)
        self.room = room
        self.origin = addr
        self.port = self.server.getsockname()[1]

        threading.Thread(target=self.receive_message, daemon=True).start()

    def receive_message(self):
        while True:
            packet, addr = self.server.recvfrom(2048)
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
                self.room.broadcast(addr,packet.body)
                print(f"{datetime.datetime.now()} [INCOMING MESSAGE] {addr} {packet.body}")

    def send_message(self,addr, msg: str):

        packet = Message(
            addr[0],
            addr[1],
            constant.TYPE_MESSAGE,
            msg
        ).encode()

        self.server.sendto(packet, self.origin)

class ChatRoom(Server):
            
    members : list[Stream] = list()
    def __init__(self, ip: str, port: int) -> None:
        super().__init__(ip, port)
        threading.Thread(target=self.handshake_listener, daemon=True).start()
    
    def handshake_listener(self):
        while True:
            packet, addr = self.server.recvfrom(2048)
            
            messages = Message.decode(packet)
            if(messages.body.encode() == PASS):
                stream = Stream(self, addr, self.ip)

                packet = Message(self.server.getsockname()[0], 
                                 self.server.getsockname()[1], 
                                 constant.SERVER_AUTH_SUCCESS,
                                 str(stream.port)).encode()
                self.server.sendto(packet, addr)
                # time.sleep(2)
                # self.server.sendto(str(stream.port).encode(), addr)
                self.members.append(stream)
                print(f"[NEW STREAM] STREAM({stream.origin}) CONNECTED")
                pass
            else:
                packet = Message(self.server.getsockname()[0], self.server.getsockname()[1], constant.SERVER_AUTH_FAIL, "Wrong Password")
                self.server.sendto(packet, addr)

    def broadcast(self, addr, msg): 
        for member in self.members:
            if member.origin == addr: continue
            member.send_message(addr, msg)

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
    
