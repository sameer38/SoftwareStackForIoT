import os
import socket
from subprocess import call
import pyDH
import speck
import time

HEADER = 64
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
    message = ""
    for x in SPECK.encrypt(msg):
        message += str(x) + ","
    message = message.encode(FORMAT)
    CLIENT.send(message)
    time.sleep(1)


def save_file():
    """Saves file from server

    Returns:
        string: name of the saved file_
    """

    file_name = CLIENT.recv(1024).decode(FORMAT)
    program_file = open(file_name, "wb")
    while True:
        program_content = CLIENT.recv(1024)
        if program_content.decode(FORMAT) == EOF:
            break
        program_file.write(program_content)
    program_file.close()
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
            print(SHARED_KEY)
            KEY = int(SHARED_KEY, 16) & ((2 ** 128) - 1)
            print(KEY)
            SPECK = speck.Speck(KEY)

            print("[CONNECTION] Received reply from :", addr[0])

            server_addr = (addr[0], PORT)

            CLIENT = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            CLIENT.connect(server_addr)
            print("[CONNECTED] Connected to server :", addr[0])
            server.sendto(CONNECTED_MESSAGE.encode(
                FORMAT), ('<broadcast>', 37020))

            send("Hello")
            send("HI")
            send("sadfasdfasf")
            send(DISCONNECT_MESSAGE)

            if flag:
                save_file()
                setup_file = save_file()
                CLIENT.send(DISCONNECT_MESSAGE.encode(FORMAT))
                CLIENT.close()
                os.chmod(setup_file, 0o755)
                call("./" + setup_file, shell=True)

            break


if __name__ == "__main__":
    main()
