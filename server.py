import socket
import threading
import pyDH
import speck
import json
import base64


def extract_ip():
    st = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        st.connect(("10.255.255.255", 1))
        IP = st.getsockname()[0]
    except Exception:
        IP = "127.0.0.1"
    finally:
        st.close()
    return IP


# SERVER = ""
SERVER = extract_ip()
# SERVER = "10.42.0.1"

HEADER = 32
PORT = 37040
ADDR = (SERVER, PORT)
FORMAT = "utf-8"
DISCONNECT_MESSAGE = "!DISCONNECT"
CONNECT_MESSAGE = "!CONNECT"
CONNECT_SECOND_MESSAGE = "!CONNECT_SECOND"
CONNECTED_MESSAGE = "!CONNECTED"
SERVER_CONNECT_MESSAGE = "!SERVER_CONNECT"
EOF = "!EOF"
MESSAGE_TYPE = "!DATA"
FILE_TYPE = "!FILE"


diffie_hellman = pyDH.DiffieHellman()
public_key = diffie_hellman.gen_public_key()
shared_key = {}

server_connect_message = {"type": SERVER_CONNECT_MESSAGE, "public_key": public_key}
server_connect_message = json.dumps(server_connect_message)

send_files_set = set()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

# receives requests from clients to conenct and send a connect message back to confirm


def lookup():
    """Listens to clients for incoming requests"""

    # For listening to requests from clients
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    client.bind(("", 37020))

    # For sending replies to clients
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    server.settimeout(1)

    while True:

        data, addr = client.recvfrom(1024)
        if not data:
            continue

        data = data.decode(FORMAT)
        data = json.loads(data)
        type = data["type"]

        if type == CONNECT_MESSAGE:
            print(f"[INFO] {addr[0]} wants to connect")
            public_key = data["public_key"]
            receive_files = data["receive_files"]
            if receive_files:
                send_files_set.add(addr[0])
            shared_key[addr[0]] = diffie_hellman.gen_shared_key(int(public_key))
            server.sendto(server_connect_message.encode(FORMAT), (addr[0], 37030))

        elif type == CONNECTED_MESSAGE:
            continue


def handle_file(current_payload):
    """Saves file from server

    Returns:
        string: name of the saved file
    """

    file = open(current_payload["file"], "wb")
    contents = current_payload["data"]
    contents = contents.encode("utf-8")
    contents = base64.b64decode(contents)
    file.write(contents)
    file.close()

    return current_payload["file"]


def send(connection_socket, data, speck):
    """sends data to the client

    Args:
        msg (string): data to send
    """
    payload = {"type": MESSAGE_TYPE, "data": data}
    payload = json.dumps(payload)
    payload = speck.encrypt(payload)
    payload = f"{len(payload):<{HEADER}}" + payload
    payload = payload.encode(FORMAT)
    connection_socket.send(payload)


def send_file(connection_socket, file_name, save_file_name, speck, script, end=True):
    """_summary_

    Args:
        connection_socket (_type_): _description_
        file_name (_type_): _description_
        save_file_name (_type_): _description_
        speck (_type_): _description_
        script (_type_): _description_
        end (bool, optional): _description_. Defaults to True.
    """
    payload = {"type": FILE_TYPE, "file": save_file_name, "end": end, "script": script}
    file = open(file_name, "r")
    contents = file.read()
    payload["data"] = contents
    file.close()
    payload = json.dumps(payload)
    payload = speck.encrypt(payload)
    payload = json.dumps(payload)
    payload = f"{len(payload):<{HEADER}}" + payload
    payload = payload.encode(FORMAT)
    connection_socket.send(payload)


def receive_data():
    pass


def handle_client(connection_socket, addr):
    """Handles the connected clients

    Args:
        conn : connection to the client
        addr : addr of the connected client
    """
    key = int(shared_key[addr[0]], 16) & ((2**128) - 1)
    speck_obj = speck.Speck(key)

    print(f"[NEW CONNECTION] {addr} connected.")

    if addr[0] in send_files_set:
        send_file(connection_socket, "Demo/cam.py", "cam.py", speck_obj, False, False)
        send_file(
            connection_socket,
            "Demo/startScript.sh",
            "start_script.sh",
            speck_obj,
            True,
            True,
        )
        send_files_set.remove(addr[0])

    payload_length = 0
    payload = ""
    try:
        while True:
            payload_next = connection_socket.recv(1024)

            if (not payload) and (not payload_next):
                print("[Info] Connection Closed")
                connection_socket.close()
                break

            payload += payload_next.decode(FORMAT)
            payload_length = int(payload[:HEADER])
            payload = payload[HEADER:]

            while len(payload) < payload_length:
                payload_next = connection_socket.recv(1024)
                payload += payload_next.decode(FORMAT)

            current_payload = payload[:payload_length]
            payload = payload[payload_length:]
            current_payload = json.loads(current_payload)
            current_payload = speck_obj.decrypt(current_payload)
            current_payload = json.loads(current_payload)
            type = current_payload["type"]

            if type == MESSAGE_TYPE:
                if current_payload["data"] == DISCONNECT_MESSAGE:
                    print(f"[{addr}] Disconnected")
                    break
                print(f"[{addr}] {current_payload['data']}")
            elif type == FILE_TYPE:
                handle_file(current_payload)
    except Exception as e:
        print(e)
    connection_socket.close()
    # print("here")


def start():
    """Starts the server"""
    lookup_thread = threading.Thread(target=lookup)
    lookup_thread.start()

    server.listen()
    print(f"[LISTENING] Server is listening on {SERVER}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        # print(f"[ACTIVE CONNECTIONS] {number_of_connected_clients}")


print("[STARTING] server is starting...")
start()
