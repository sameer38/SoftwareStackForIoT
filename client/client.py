import os
import socket
from subprocess import call
import pyDH
import speck_using
import json
import base64


class client:

    HEADER = 32
    PORT = 37040
    FORMAT = "utf-8"
    DISCONNECT_MESSAGE = "!DISCONNECT"
    CONNECT_MESSAGE = "!CONNECT"
    CONNECTED_MESSAGE = "!CONNECTED"
    SERVER_CONNECT_MESSAGE = "!SERVER_CONNECT"
    MESSAGE_TYPE = "!DATA"
    FILE_TYPE = "!FILE"
    EOF = "!EOF"
    AUTHENTICATED_MESSAGE = "!AUTHENTICATED"
    INVALID_MESSAGE = "!INVALID"

    def connect(self, receive_files=False):
        """Connects to the server"""
        self.main(receive_files)

    def send_data(self, payload):
        payload = json.dumps(payload)
        payload = self.speck.encrypt(payload)
        payload = json.dumps(payload)
        payload = f"{len(payload):<{self.HEADER}}" + payload
        payload = payload.encode(self.FORMAT)
        self.connection_socket.send(payload)

    def send(self, data):
        """sends data to the server

        Args:
            msg (string): data to send
        """
        payload = {"type": self.MESSAGE_TYPE, "data": data}
        self.send_data(payload)

    def send_file(self, file_path, file_name):
        """sends file to the server

        Args:
            file_path (string): path of file to send
            file_name (string): name of the file
        """
        payload = {"type": self.FILE_TYPE, "file": file_name}
        self.send_data(payload)

        file = open(file_path, "rb")

        contents = file.read(128)
        while contents:
            contents = base64.b64encode(contents).decode("utf-8")
            self.send_data(contents)
            contents = file.read(128)

        file.close()
        self.send_data(self.EOF)

    def receive_data(self, payload):

        if len(payload) < self.HEADER:
            payload_next = self.connection_socket.recv(1024)
            payload_next = payload_next.decode(self.FORMAT)
            payload = payload + payload_next

        payload_length = int(payload[: self.HEADER])
        payload = payload[self.HEADER :]

        while len(payload) < payload_length:
            payload_next = self.connection_socket.recv(1024)
            payload += payload_next.decode(self.FORMAT)

        current_payload = payload[:payload_length]
        payload = payload[payload_length:]
        current_payload = json.loads(current_payload)
        current_payload = self.speck.decrypt(current_payload)
        current_payload = json.loads(current_payload)

        return (current_payload, payload)

    def save_file(self, file, payload):

        file = open(file, "w")
        while True:
            (current_payload, payload) = self.receive_data(payload)

            if current_payload == self.EOF:
                break

            file.write(current_payload)

        file.close()
        return payload

    def handle_file(self, payload=""):
        """Saves file from server

        Returns:
            string: name of the saved file
        """

        end = False
        file_name = ""

        while not end:

            (current_payload, payload) = self.receive_data(payload)
            end = current_payload["end"]
            file = current_payload["file"]

            if current_payload["script"]:
                file_name = file

            payload = self.save_file(file, payload)

        return file_name

    def __init__(self, receive_files=False):

        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        server.settimeout(1)

        # For listening for replies from server
        server_listener = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
        )
        server_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_listener.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        server_listener.bind(("", 37030))
        server_listener.settimeout(1)

        diffie_hellman = pyDH.DiffieHellman()

        public_key = diffie_hellman.gen_public_key()

        payload = {
            "type": self.CONNECT_MESSAGE,
            "public_key": public_key,
            "receive_files": receive_files,
        }
        payload = json.dumps(payload)
        payload = payload.encode(self.FORMAT)

        while True:

            # Sending request to server for connection
            # server.sendto(payload, ("localhost", 37020))
            server.sendto(payload, ("<broadcast>", 37020))
            print("[CONNECTING] Sending request to connect")

            # waiting for server to reply
            try:
                data, addr = server_listener.recvfrom(1024)
            except socket.timeout:
                continue

            data = data.decode(self.FORMAT)
            data = json.loads(data)

            type = data["type"]
            server_key = data["public_key"]

            if type == self.SERVER_CONNECT_MESSAGE:

                self.shared_key = diffie_hellman.gen_shared_key(int(server_key))
                self.key = int(self.shared_key, 16) & ((2**128) - 1)
                self.speck = speck_using.Speck(self.key)

                print("[CONNECTION] Received reply from :", addr[0])

                server_addr = (addr[0], self.PORT)

                self.connection_socket = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM
                )
                self.connection_socket.connect(server_addr)
                print("[CONNECTED] Connected to server :", addr[0])

                payload = {"type": self.CONNECTED_MESSAGE}
                payload = json.dumps(payload)
                payload = payload.encode(self.FORMAT)

                # server.sendto(payload, ("localhost", 37020))
                server.sendto(payload, ("<broadcast>", 37020))

                authenticated = False
                payload = ""
                has_auth_token = False

                if os.path.exists("./auth.config"):
                    auth_file = open("auth.config", "r")
                    auth_token = auth_file.read()
                    if auth_token != "":
                        has_auth_token = True
                    auth_file.close()

                if not has_auth_token:
                    self.send(123)
                    (current_payload, payload) = self.receive_data(payload)

                while not authenticated:
                    if has_auth_token:
                        self.send(int(auth_token))
                    else:
                        pin = input("Please enter the pin for the server : ")
                        self.send(int(pin))
                    (current_payload, payload) = self.receive_data(payload)
                    authenticated = (
                        current_payload["data"] == self.AUTHENTICATED_MESSAGE
                    )
                    if authenticated and not has_auth_token:
                        (current_payload, payload) = self.receive_data(payload)
                        auth_token = current_payload["data"]
                        auth_file = open("auth.config", "w+")
                        auth_file.write(str(auth_token))
                        auth_file.close()

                    if not authenticated:
                        print("Invalid")
                        has_auth_token = False
                    if current_payload["data"] == self.DISCONNECT_MESSAGE:
                        print("Maximum attempts reached. Disconnected")
                        self.connection_socket.close()
                        return

                if receive_files:
                    (current_payload, payload) = self.receive_data(payload)

                    program_list = current_payload["data"]
                    print("List of programs : ")
                    for i, a in enumerate(program_list):
                        print(f"{i + 1}. {a}")

                    program = int(input("Choose a program to execute : "))
                    while program > len(program_list) or program < 1:
                        program = input("Invalid choice please enter again : ")

                    self.send(program_list[program - 1])

                    setup_file = self.handle_file(payload)
                    self.send(self.DISCONNECT_MESSAGE)
                    self.connection_socket.close()
                    os.chmod(setup_file, 0o755)
                    call("./" + setup_file, shell=True)
                break


if __name__ == "__main__":
    client(True)
