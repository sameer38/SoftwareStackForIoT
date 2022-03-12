import os
import socket
from subprocess import call
import pyDH
import speck
import json

HEADER = 32
PORT = 37040
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
CONNECT_MESSAGE = "!CONNECT"
CONNECTED_MESSAGE = "!CONNECTED"
SERVER_CONNECT_MESSAGE = "!SERVER_CONNECT"
EOF = "!EOF"

CLIENT = None
SHARED_KEY = None
KEY = None
SPECK = None


def connect():
    """Connects to the server
    """
    main(False)


def send(msg):
    """sends data to the server

    Args:
        msg (string): data to send
    """
    message = SPECK.encrypt(msg)
    message = json.dumps(message)
    message = f'{len(message):<{HEADER}}' + message
    message = message.encode(FORMAT)
    CLIENT.send(message)


def save_file():
    """Saves file from server

    Returns:
        string: name of the saved file_
    """

    encrypted_message = ''
    msg = ''
    file_name = ''
    new_file = True
    files = 0

    received_message = CLIENT.recv(1024)
    encrypted_message += received_message.decode(FORMAT)
    msg_length = int(encrypted_message[:HEADER])
    total_number_of_files = encrypted_message[HEADER: HEADER + msg_length]
    total_number_of_files = json.loads(total_number_of_files)
    total_number_of_files = int(SPECK.decrypt(total_number_of_files))
    encrypted_message = encrypted_message[HEADER + msg_length:]

    while True:
        if files == total_number_of_files:
            break
        received_message = CLIENT.recv(1024)
        if not received_message:
            break
        encrypted_message += received_message.decode(FORMAT)
        if not encrypted_message:
            break
        while True:
            if not encrypted_message:
                break
            msg_length = int(encrypted_message[:HEADER])

            if len(encrypted_message[HEADER:]) >= msg_length:
                current_message = encrypted_message[HEADER: HEADER + msg_length]
                encrypted_message = encrypted_message[HEADER + msg_length:]
                msg = json.loads(current_message)
                msg = SPECK.decrypt(msg)
                if new_file:
                    file_name = msg
                    program_file = open(msg, "w")
                    new_file = False
                elif msg != EOF:
                    program_file.write(msg)
                if msg == EOF:
                    new_file = True
                    files += 1
                    program_file.close()

            else:
                break

    return file_name


def main(flag=True):
    """ Connects to the server

    Args:
        flag (bool, optional): Flag to recevice files from server or not. Defaults to True.
    """
    global SHARED_KEY, KEY, CLIENT, SPECK

    # For sending connect requests to server
    server = socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    server.settimeout(1)

    # For listening for replies from server
    server_listener = socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    server_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_listener.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    server_listener.bind(("", 37030))
    server_listener.settimeout(1)

    diffie_hellman = pyDH.DiffieHellman()

    public_key = diffie_hellman.gen_public_key()

    connect_message = CONNECT_MESSAGE + " " + str(public_key)

    tries = 0
    while True:
        tries += 1

        if tries > 10:
            print("[ERROR] Connection failed after 10 attempts")
            exit()

        # Sending request to server for connection
        server.sendto(connect_message.encode(FORMAT), ('<broadcast>', 37020))
        print("[CONNECTING] Sending request to connect")

        # waiting for server to reply
        try:
            data, addr = server_listener.recvfrom(1024)
        except socket.timeout:
            continue

        data_decoded = data.decode(FORMAT)
        data_split = data_decoded.split(" ")

        if data_split[0] == SERVER_CONNECT_MESSAGE:

            SHARED_KEY = diffie_hellman.gen_shared_key(int(data_split[1]))
            KEY = int(SHARED_KEY, 16) & ((2 ** 128) - 1)
            SPECK = speck.Speck(KEY)

            print("[CONNECTION] Received reply from :", addr[0])

            server_addr = (addr[0], PORT)

            CLIENT = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            CLIENT.connect(server_addr)
            print("[CONNECTED] Connected to server :", addr[0])
            server.sendto(CONNECTED_MESSAGE.encode(
                FORMAT), ('<broadcast>', 37020))

            if flag:
                setup_file = save_file()
                send(DISCONNECT_MESSAGE)
                CLIENT.close()
                os.chmod(setup_file, 0o755)
                call("./" + setup_file, shell=True)

            break


if __name__ == "__main__":
    main()
