from dataclasses import dataclass
import constant
@dataclass
class Message:
    source_ip: str
    source_port: int
    header: str
    source_username: str
    signature: int
    body: str

    def encode(self) -> bytes:
        return (self.source_ip + '\n' + str(self.source_port) + '\n' + self.header + '\n' + self.source_username + '\n' + str(self.signature) + '\n' + self.body + '\n').encode()

    @staticmethod
    def decode(packet: bytes):
        messages = packet.decode().splitlines()
        length = len(messages)
        body = "\n".join(messages[5:])
        # for i in messages[5:(length - 1)]:
        #     body += i + '\n'
        
        # body += messages[length - 1]

        return Message(messages[0], int(messages[1]), messages[2], messages[3], int(messages[4]), body)

if(__name__ == '__main__'):
    message = Message("192.168.71.8", 5049, constant.TYPE_AUTH, "123456")
    message2 = Message.decode(message.encode())

    print(message.source_ip == message2.source_ip)
    print(message.source_port == message2.source_port)
    print(message.header, message2.header,message.header == message2.header)
    print(message.body, message2.body, message.body == message2.body)
    
