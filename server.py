import socket
import threading
import time

HEADER = 64
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

numberOfConnectedClients = 0
connectingClientsSet = set()
sentFiles = set()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

# receives requests from clients to conenct and send a connect message back to confirm
def lookup():

    # For listening to requests from clients
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    client.bind(("", 37020))

    # For sending replies to clients
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    server.settimeout(1)

    while True:

        data, addr = client.recvfrom(1024)
        if data.decode(FORMAT) == CONNECT_MESSAGE:
            connectingClientsSet.add(addr)
            print(f"[INFO] {addr[0]} wants to connect")
            server.sendto(SERVER_CONNECT_MESSAGE.encode(FORMAT), ('<broadcast>', 37030))

        elif data.decode(FORMAT) == CONNECTED_MESSAGE:
            connectingClientsSet.remove(addr)


def sendFile(conn, fileName, saveFileName):

    conn.send(saveFileName.encode(FORMAT))
    f = open(fileName, "rb")
    l = f.read(1024)
    while (l):
        conn.send(l)
        l = f.read(1024)

    f.close()
    time.sleep(0.5)
    conn.send(EOF.encode(FORMAT))

# handles the connected clients
def handle_client(conn, addr):
    global numberOfConnectedClients
    print(f"[NEW CONNECTION] {addr} connected.")
    numberOfConnectedClients += 1
    removal = True

    if addr[0] not in sentFiles:
        removal = False
        sendFile(conn, "q.py", "p.py")
        time.sleep(1)
        sendFile(conn, "a.sh", "b.sh")
        sentFiles.add(addr[0])

    connected = True
    while connected:
        msg = conn.recv(1024).decode(FORMAT)
        if msg == DISCONNECT_MESSAGE:
            if removal:
                sentFiles.remove(addr[0])
            numberOfConnectedClients -= 1
            connected = False
        if msg == "":
            print("[Error] Connection Closed")
            break
        print(f"[{addr}] {msg}")

    conn.close()


def start():

    lookupThread = threading.Thread(target=lookup)
    lookupThread.start()

    server.listen()
    print(f"[LISTENING] Server is listening on {SERVER}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {numberOfConnectedClients}")


print("[STARTING] server is starting...")
start()
