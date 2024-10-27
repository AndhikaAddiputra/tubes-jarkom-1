import sys
import socket
import threading
import datetime
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit
from PyQt5.QtCore import pyqtSlot
from message import Message  # Import sesuai dengan struktur aplikasi sebelumnya
from encrypt import RSA
import constant



# Implementasi kode client UDP
class Client:
    def __init__(self):
        self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.clientSocket.bind((socket.gethostbyname(socket.gethostname()), 0))
        self.chatAddress = ("-1", -1)

    def connect(self, addr, password: str) -> tuple[bool, str]:
        packet = Message(self.clientSocket.getsockname()[0], self.clientSocket.getsockname()[1], constant.TYPE_AUTH, password).encode()
        self.clientSocket.sendto(packet, addr)

        packet, address = self.clientSocket.recvfrom(2048)
        if address == addr:
            packet = Message.decode(packet)
            if packet.header == constant.SERVER_AUTH_SUCCESS:
                self.chatAddress = (addr[0], int(packet.body))
                return (True, "")
            else:
                return (False, packet.body)
        else:
            return (False, "Unauthorized!")

    def receive_message(self):
        while True and self.chatAddress[1] != -1:
            packet, addr = self.clientSocket.recvfrom(4096)
            if addr == self.chatAddress:
                packet = Message.decode(packet)
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                return f"{timestamp} [{packet.source_ip}:{packet.source_}] {packet.body}"

    def send_message(self, message: str):
        if self.chatAddress[1] != -1:
            packet = Message(self.clientSocket.getsockname()[0], 
                             self.clientSocket.getsockname()[1], 
                             constant.TYPE_MESSAGE,
                             self.username,
                             0, 
                             message).encode()
            
            self.clientSocket.sendto(packet, self.chatAddress)
    
    def disconnect(self):
        packet = Message(self.clientSocket.getsockname()[0], self.clientSocket.getsockname()[1], constant.TYPE_DISCONNECT, "").encode()
        self.clientSocket.sendto(packet, self.chatAddress)
        self.chatAddress = ("-1", -1)


# Implementasi UI PyQt5
class ChatApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.client = Client()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Ganyang Fufufafa")
        
        # Layout utama untuk menampilkan semua tahap
        self.centralWidget = QWidget(self)
        self.setCentralWidget(self.centralWidget)
        self.layout = QVBoxLayout(self.centralWidget)
        
        # Bagian Login
        self.login_label = QLabel("Welvome to GFChatroom", self)
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
        username = self.username_input.text()
        password = self.password_input.text()
        # Kode login (implementasi sesuai struktur kode login yang ada)
        
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
        self.chat_display.append(f"{timestamp} You: {message}")
        self.chat_input.clear()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatApp()
    sys.exit(app.exec_())
