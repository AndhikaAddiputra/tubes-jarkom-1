import sys
import socket
import threading
import datetime
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit
from PyQt5.QtCore import pyqtSlot
from message import Message  # Import sesuai dengan struktur aplikasi sebelumnya
from encrypt import RSA
import constant

class Message:
    def __init__(self, source_ip, source_port, header, source_username, signature, body):
        self.source_ip = source_ip
        self.source_port = source_port
        self.header = header
        self.source_username = source_username
        self.signature = signature
        self.body = body

    def encode(self):
        # Ubah semua bagian yang bukan string ke string sebelum digabungkan
        return (
            str(self.source_ip) + '\n' +
            str(self.source_port) + '\n' +
            str(self.header) + '\n' +
            str(self.source_username) + '\n' +
            str(self.signature) + '\n' +
            str(self.body) + '\n'
        ).encode()

    @staticmethod
    def decode(encoded_message):
        parts = encoded_message.decode().split('\n')
        source_ip = parts[0]
        source_port = int(parts[1])
        header = parts[2]
        source_username = parts[3]
        signature = int(parts[4])
        body = parts[5]
        return Message(source_ip, source_port, header, source_username, signature, body)

class Client:
    def __init__(self, username):
        self.username = username
        self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.clientSocket.bind((socket.gethostbyname(socket.gethostname()), 0))
        self.chatAddress = ("-1", -1)

        # Setup RSA
        (self.priv_key, self.pub_key, self.n) = RSA.generate_key()
        self.rsa = RSA(self.priv_key, self.n)
        self.server_pub_key = None

    def connect(self, addr, password: str) -> tuple[bool, str]:
        # Kirim kunci publik client ke server
        pub_key_message = Message(
            self.clientSocket.getsockname()[0],
            self.clientSocket.getsockname()[1],
            constant.TYPE_REQ_PUB,
            self.username,
            0,
            f"{self.pub_key}|{self.n}"
        ).encode()
        self.clientSocket.sendto(pub_key_message, addr)

        # Terima kunci publik server
        packet, address = self.clientSocket.recvfrom(2048)
        if address == addr:
            packet = Message.decode(packet)
            if packet.header == constant.TYPE_RESPONSE_PUB:
                server_key = packet.body.split('|')
                self.server_pub_key = (int(server_key[0]), int(server_key[1]))

        # Kirim autentikasi setelah enkripsi password dengan kunci publik server
        encrypted_password = self.rsa.encrypt(password, self.server_pub_key)
        auth_message = Message(
            self.clientSocket.getsockname()[0],
            self.clientSocket.getsockname()[1],
            constant.TYPE_AUTH,
            self.username,
            0,
            encrypted_password
        ).encode()
        self.clientSocket.sendto(auth_message, addr)

        packet, address = self.clientSocket.recvfrom(2048)
        if address == addr:
            packet = Message.decode(packet)
            if packet.header == constant.SERVER_AUTH_SUCCESS:
                self.chatAddress = (addr[0], int(packet.body.split('|')[0]))
                return (True, "")
            else:
                return (False, packet.body)
        else:
            return (False, "Unauthorized!")

    def receive_message(self):
        while True and self.chatAddress[1] != -1:
            packet, addr = self.clientSocket.recvfrom(2048)
            if addr == self.chatAddress:
                packet = Message.decode(packet)
                decrypted_body = self.rsa.decrypt(packet.body)
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                return f"{timestamp} [{packet.source_username}] {decrypted_body}"

    def send_message(self, message: str):
        if self.chatAddress[1] != -1:
            encrypted_message = self.rsa.encrypt(message, self.server_pub_key)
            packet = Message(
                self.clientSocket.getsockname()[0],
                self.clientSocket.getsockname()[1],
                constant.TYPE_MESSAGE,
                self.username,
                0,
                encrypted_message
            ).encode()
            self.clientSocket.sendto(packet, self.chatAddress)

    def disconnect(self):
        packet = Message(
            self.clientSocket.getsockname()[0],
            self.clientSocket.getsockname()[1],
            constant.TYPE_DISCONNECT,
            self.username,
            0,
            ""
        ).encode()
        self.clientSocket.sendto(packet, self.chatAddress)
        self.chatAddress = ("-1", -1)


# UI PyQt5
class ChatApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.username = ""
        self.client = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Ganyang Fufufafa")
        
        # Layout utama untuk menampilkan semua tahap
        self.centralWidget = QWidget(self)
        self.setCentralWidget(self.centralWidget)
        self.layout = QVBoxLayout(self.centralWidget)
        
        # Bagian Login
        self.login_label = QLabel("Welcome to GFChatroom", self)
        self.layout.addWidget(self.login_label)
        
        self.username_input = QLineEdit(self)
        self.username_input.setPlaceholderText("Enter username")
        self.layout.addWidget(self.username_input)
        
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter password")
        self.layout.addWidget(self.password_input)
        
        self.login_button = QPushButton("Login", self)
        self.login_button.clicked.connect(self.handle_login)
        self.layout.addWidget(self.login_button)
        
        # Bagian Join Room
        self.join_label = QLabel("Join Roomchat", self)
        self.layout.addWidget(self.join_label)
        self.join_label.setVisible(False)

        self.ip_input = QLineEdit(self)
        self.ip_input.setPlaceholderText("Enter room IP")
        self.layout.addWidget(self.ip_input)
        self.ip_input.setVisible(False)

        self.port_input = QLineEdit(self)
        self.port_input.setPlaceholderText("Enter room port")
        self.layout.addWidget(self.port_input)
        self.port_input.setVisible(False)

        self.room_password_input = QLineEdit(self)
        self.room_password_input.setEchoMode(QLineEdit.Password)
        self.room_password_input.setPlaceholderText("Enter room password")
        self.layout.addWidget(self.room_password_input)
        self.room_password_input.setVisible(False)

        self.join_button = QPushButton("Join Room", self)
        self.join_button.clicked.connect(self.handle_join_room)
        self.layout.addWidget(self.join_button)
        self.join_button.setVisible(False)
        
        # Bagian Roomchat
        self.chat_display = QTextEdit(self)
        self.chat_display.setReadOnly(True)
        self.layout.addWidget(self.chat_display)
        self.chat_display.setVisible(False)

        self.chat_input = QLineEdit(self)
        self.chat_input.setPlaceholderText("Enter your message")
        self.layout.addWidget(self.chat_input)
        self.chat_input.setVisible(False)

        self.send_button = QPushButton("Send", self)
        self.send_button.clicked.connect(self.send_message)
        self.layout.addWidget(self.send_button)
        self.send_button.setVisible(False)

        self.show()

    @pyqtSlot()
    def handle_login(self):
        self.username = self.username_input.text()
        password = self.password_input.text()
        self.client = Client(self.username)
        
        success = True  # Anggap login berhasil untuk contoh ini
        if success:
            self.login_label.setVisible(False)
            self.username_input.setVisible(False)
            self.password_input.setVisible(False)
            self.login_button.setVisible(False)
            
            self.join_label.setVisible(True)
            self.ip_input.setVisible(True)
            self.port_input.setVisible(True)
            self.room_password_input.setVisible(True)
            self.join_button.setVisible(True)

    @pyqtSlot()
    def handle_join_room(self):
        ip = self.ip_input.text()
        port = int(self.port_input.text())
        room_password = self.room_password_input.text()
        
        result, msg = self.client.connect((ip, port), room_password)
        if result:
            self.join_label.setVisible(False)
            self.ip_input.setVisible(False)
            self.port_input.setVisible(False)
            self.room_password_input.setVisible(False)
            self.join_button.setVisible(False)

            self.chat_display.setVisible(True)
            self.chat_input.setVisible(True)
            self.send_button.setVisible(True)
            
            # Mulai thread untuk menerima pesan
            threading.Thread(target=self.receive_message_thread, daemon=True).start()

    def receive_message_thread(self):
        while True:
            msg = self.client.receive_message()
            if msg:
                self.chat_display.append(msg)

    @pyqtSlot()
    def send_message(self):
        message = self.chat_input.text()
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        self.client.send_message(message)
        self.chat_display.append(f"{timestamp} {self.username}: {message}")
        self.chat_input.clear()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatApp()
    sys.exit(app.exec_())
