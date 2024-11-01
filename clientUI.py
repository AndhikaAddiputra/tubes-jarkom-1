import tkinter as tk
from tkinter import messagebox, simpledialog
import socket
import threading
import constant
from datetime import datetime
from encrypt import RSA
from message import Message
from client import Client

class ChatClientUI:
    def __init__(self, client):
        self.client = client
        self.client.ui = self 
        self.root = tk.Tk()
        self.root.title("GanyangFufufa Chat Client")

        # Login Frame
        self.login_frame = tk.Frame(self.root)
        self.login_frame.pack(padx=10, pady=10)

        self.username_label = tk.Label(self.login_frame, text="Username:")
        self.username_label.grid(row=0, column=0)
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1)

        self.password_label = tk.Label(self.login_frame, text="Password:")
        self.password_label.grid(row=1, column=0)
        self.password_entry = tk.Entry(self.login_frame, show='*')
        self.password_entry.grid(row=1, column=1)

        self.register_button = tk.Button(self.login_frame, text="Register", command=self.register)
        self.register_button.grid(row=2, column=0, pady=5)

        self.login_button = tk.Button(self.login_frame, text="Login", command=self.login)
        self.login_button.grid(row=2, column=1, pady=5)

        # Chat Frame
        self.chat_frame = tk.Frame(self.root)
        self.chat_text = tk.Text(self.chat_frame, state=tk.DISABLED, width=50, height=15)
        self.chat_text.pack(padx=10, pady=10)

        self.message_entry = tk.Entry(self.chat_frame, width=40)
        self.message_entry.pack(side=tk.LEFT, padx=10)
        self.send_button = tk.Button(self.chat_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT, padx=10)

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        success, msg = self.client.doActionCentral(constant.TYPE_REGISTER_CENTRAL, username, password)
        if not success:
            messagebox.showerror("Error", f"Registration Failed: {msg}")
        else:
            messagebox.showinfo("Success", "Registration successful!")

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        success, msg = self.client.doActionCentral(constant.TYPE_LOGIN_CENTRAL, username, password)
        if not success:
            messagebox.showerror("Error", f"Login Failed: {msg}")
        else:
            messagebox.showinfo("Success", "Login successful!")
            self.join_room()

    def join_room(self):
        chat_ip = simpledialog.askstring("Chat Room", "Enter the room IP to connect:")
        chat_port = simpledialog.askinteger("Chat Room", "Enter the room port to connect:")
        chat_password = simpledialog.askstring("Chat Room", "Enter the room password to connect:", show='*')

        result = self.client.connect((chat_ip, chat_port), chat_password)
        if result[0]:
            threading.Thread(target=self.client.receive_message, daemon=True).start()
            messagebox.showinfo("Success", "Connected to chat room!")
            self.login_frame.pack_forget()  # Sembunyikan frame login
            self.chat_frame.pack(padx=10, pady=10)
        else:
            messagebox.showerror("Error", "Connection failed.")

    def chat_room(self):
        self.login_frame.pack_forget()
        self.chat_frame.pack(padx=10, pady=10)
        chat_ip = tk.simpledialog.askstring("Chat Room", "Enter the room IP to connect:")
        chat_port = tk.simpledialog.askinteger("Chat Room", "Enter the room port to connect:")
        chat_password = tk.simpledialog.askstring("Chat Room", "Enter the room password to connect:", show='*')

        result = self.client.connect((chat_ip, chat_port), chat_password)
        if result[0]:
            threading.Thread(target=client.receive_message, daemon=True).start()
        else:
            messagebox.showerror("Error", "Connection failed.")

    def send_message(self):
        message = self.message_entry.get()
        if message:
            timestamp = datetime.now().strftime("%H:%M:%S")
            client.send_message(message)
            self.message_entry.delete(0, tk.END)
            self.display_message(self.client.username, message, timestamp)
            print("Message sent:", message)
    
    def receive_message(self): 
        # print("AHLAN")
        while True and self.chatAddress[1] != -1:
            packet, addr = self.clientSocket.recvfrom(4096)
            # print("ANJG")
            # address = (chatIp, chatPort)
            if(addr == self.chatAddress): # authorized
                packet = Message.decode(packet)
                decrypted_message = self.rsa.decrypt(packet.body)
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"Received message from {packet.source_username}: {decrypted_message}")  # Debugging
                print("About to display message in UI")
                if hasattr(self.ui, 'display_message'):
                    self.ui.display_message(packet.source_username, decrypted_message, timestamp)


    def on_closing(self):
        self.client.disconnect()
        self.root.destroy()

    def display_message(self, username, message, timestamp):
        self.chat_text.config(state=tk.NORMAL)
        self.chat_text.insert(tk.END, f"[{timestamp} {username}] {message}\n")
        self.chat_text.config(state=tk.DISABLED)

if __name__ == "__main__":
    client = Client()
    ChatClientUI(client)
