import os
import socket
from subprocess import call
import pyDH

HEADER = 64
PORT = 37040
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
CONNECT_MESSAGE = "!CONNECT"
CONNECTED_MESSAGE = "!CONNECTED"
SERVER_CONNECT_MESSAGE = "!SERVER_CONNECT"
EOF = "!EOF"

client = None
shared_key = None


def saveFile():

    fileName = client.recv(1024).decode(FORMAT)
    programFile = open(fileName, "wb")
    while True:
        programContent = client.recv(1024)
        if programContent.decode(FORMAT) == EOF:
            break
        programFile.write(programContent)
    programFile.close()
    return fileName


def main(flag=True):

    # For sending connect requests to server
    server = socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    server.settimeout(1)

    # For listening for replies from server
    serverListener = socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    serverListener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverListener.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    serverListener.bind(("", 37030))
    serverListener.settimeout(1)

    diffie_hellman = pyDH.DiffieHellman()

    public_key = diffie_hellman.gen_public_key()

    global CONNECT_MESSAGE
    CONNECT_MESSAGE = CONNECT_MESSAGE + " " + str(public_key)

    tries = 0
    while True:
        global client, shared_key
        tries += 1

        if tries > 10:
            print("[ERROR] Connection failed after 10 attempts")
            exit()

        # Sending request to server for connection
        server.sendto(CONNECT_MESSAGE.encode(FORMAT), ('<broadcast>', 37020))
        print("[CONNECTING] Sending request to connect")

        # waiting for server to reply
        try:
            data, addr = serverListener.recvfrom(1024)
        except socket.timeout:
            continue

        dataDecoded = data.decode(FORMAT)
        dataSplit = dataDecoded.split(" ")

        if dataSplit[0] == SERVER_CONNECT_MESSAGE:

            shared_key = diffie_hellman.gen_shared_key(int(dataSplit[1]))
            print(shared_key)

            print("[CONNECTION] Received reply from :", addr[0])

            ADDR = (addr[0], PORT)

            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(ADDR)
            print("[CONNECTED] Connected to server :", addr[0])
            server.sendto(CONNECTED_MESSAGE.encode(
                FORMAT), ('<broadcast>', 37020))

            if flag:
                saveFile()
                setupFile = saveFile()
                client.send(DISCONNECT_MESSAGE.encode(FORMAT))
                client.close()
                os.chmod(setupFile, 0o755)
                rc = call("./" + setupFile, shell=True)

            break


if __name__ == "__main__":
    main()


def connect():
    main(False)

# Send message to server


def send(msg):
    message = msg.encode(FORMAT)
    client.send(message)
