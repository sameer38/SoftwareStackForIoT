import socket
import threading
import pyDH
import speck
import json

HEADER = 32
PORT = 37040
SERVER = ""
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "!DISCONNECT"
CONNECT_MESSAGE = "!CONNECT"
CONNECT_SECOND_MESSAGE = "!CONNECT_SECOND"
CONNECTED_MESSAGE = "!CONNECTED"
SERVER_CONNECT_MESSAGE = "!SERVER_CONNECT"
EOF = "!EOF"

diffie_hellman = pyDH.DiffieHellman()
public_key = diffie_hellman.gen_public_key()
shared_key = {}

SERVER_CONNECT_MESSAGE += " " + str(public_key)

number_of_connected_clients = 0
connectingClientsSet = set()
sentFiles = set()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

# receives requests from clients to conenct and send a connect message back to confirm


def lookup():
    """ Listens to clients for incoming requests
    """

    # For listening to requests from clients
    client = socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    client.bind(("", 37020))

    # For sending replies to clients
    server = socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    server.settimeout(1)

    while True:

        data, addr = client.recvfrom(1024)
        data_decoded = data.decode(FORMAT)
        data_split = data_decoded.split(" ")

        if data_split[0] == CONNECT_MESSAGE:
            connectingClientsSet.add(addr)
            print(f"[INFO] {addr[0]} wants to connect")
            shared_key[addr[0]] = diffie_hellman.gen_shared_key(
                int(data_split[1]))
            server.sendto(SERVER_CONNECT_MESSAGE.encode(
                FORMAT), ('<broadcast>', 37030))

        elif data.decode(FORMAT) == CONNECTED_MESSAGE:
            connectingClientsSet.remove(addr)


def send(conn, message, speck):
    """sends data to the server

    Args:
        msg (string): data to send
    """
    message = speck.encrypt(message)
    message = json.dumps(message)
    message = f'{len(message):<{HEADER}}' + message
    message = message.encode(FORMAT)
    conn.send(message)


def send_file(conn, file_name, save_file_name, speck):
    """Sends file to the client

    Args:
        conn (): connection to the client
        file_name (string): name of file to send
        save_file_name (string): name of the file to be saved as
    """
    send(conn, save_file_name, speck)
    _f = open(file_name, "r")
    _l = _f.read(1024)
    while (_l):
        send(conn, _l, speck)
        _l = _f.read(1024)

    _f.close()
    send(conn, EOF, speck)


def handle_client(conn, addr):
    """Handles the connected clients

    Args:
        conn : connection to the client
        addr : addr of the connected client
    """
    global number_of_connected_clients

    key = int(shared_key[addr[0]], 16) & ((2 ** 128) - 1)
    speck_obj = speck.Speck(key)

    print(f"[NEW CONNECTION] {addr} connected.")
    number_of_connected_clients += 1
    removal = True

    if addr[0] not in sentFiles:
        removal = False
        send(conn, "2", speck_obj)
        send_file(conn, "Demo/randNum.py", "randNum.py", speck_obj)
        send_file(conn, "Demo/startScript.sh", "b.sh", speck_obj)
        sentFiles.add(addr[0])

    connected = True
    new_message = True
    msg = ''
    encrypted_message = ''
    while connected:
        received_message = conn.recv(1024)
        encrypted_message += received_message.decode(FORMAT)
        if not encrypted_message:
            break
        if new_message:
            msg_length = int(encrypted_message[:HEADER])
        if len(encrypted_message[HEADER:]) >= msg_length:
            current_message = encrypted_message[HEADER: HEADER + msg_length]
            encrypted_message = encrypted_message[HEADER + msg_length:]
            new_message = True
            msg = json.loads(current_message)
            msg = speck_obj.decrypt(msg)
            if msg == DISCONNECT_MESSAGE:
                if removal:
                    sentFiles.remove(addr[0])
                number_of_connected_clients -= 1
                connected = False
            if msg == "":
                print("[Error] Connection Closed")
                break
            print(f"[{addr}] {msg}")
        else:
            new_message = False

    conn.close()


def start():
    """Starts the server
    """
    lookup_thread = threading.Thread(target=lookup)
    lookup_thread.start()

    server.listen()
    print(f"[LISTENING] Server is listening on {SERVER}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {number_of_connected_clients}")


print("[STARTING] server is starting...")
start()
