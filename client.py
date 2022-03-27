import os
import socket
from subprocess import call
import pyDH
import speck
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
        file = open(file_path, "rb")
        contents = file.read()
        payload["data"] = base64.b64encode(contents).decode("utf-8")
        file.close()
        self.send_data(payload)

    def handle_file(self):
        """Saves file from server

        Returns:
            string: name of the saved file
        """

        end = False
        payload = ""
        file_name = ""

        while not end:

            payload_next = self.connection_socket.recv(1024)
            payload += payload_next.decode(self.FORMAT)
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
            end = current_payload["end"]
            file = current_payload["file"]
            contents = current_payload["data"]

            if current_payload["script"]:
                file_name = file

            file = open(file, "w")
            file.write(contents)
            file.close()

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
                self.speck = speck.Speck(self.key)

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

                server.sendto(payload, ("<broadcast>", 37020))

                if receive_files:
                    setup_file = self.handle_file()
                    self.send(self.DISCONNECT_MESSAGE)
                    self.connection_socket.close()
                    os.chmod(setup_file, 0o755)
                    call("./" + setup_file, shell=True)
                break


if __name__ == "__main__":
    client(True)
