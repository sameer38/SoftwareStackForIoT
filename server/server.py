import random
import socket
import threading
import pyDH
import speck_using
import json
import base64
import os


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
AUTHENTICATED_MESSAGE = "!AUTHENTICATED"
INVALID_MESSAGE = "!INVALID"


diffie_hellman = pyDH.DiffieHellman()
public_key = diffie_hellman.gen_public_key()
shared_key = {}
programs = {}
programs_list = []
authenticated_keys = {}
name_map = {}
server = None
server_connect_message = {"type": SERVER_CONNECT_MESSAGE, "public_key": public_key}
server_connect_message = json.dumps(server_connect_message)
connected_clients = set()
send_files_set = set()
clientStatusCallback = None


def add_program(program_name, script_file_path, program_file_path):
    global programs_list, programs
    script_file_name = script_file_path.split("/")[-1]
    program_file_name = program_file_path.split("/")[-1]
    programs[program_name] = {
        "program_name": program_file_name,
        "program_path": program_file_path,
        "script_name": script_file_name,
        "script_path": script_file_path,
    }

    programs_file = open("programs.config", "w+")
    json.dump(programs, programs_file)
    programs_file.close()
    programs_list = [i for i in programs]


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


def receive_data(connection_socket, payload, speck):

    if len(payload) < HEADER:
        payload_next = connection_socket.recv(1024)
        payload_next = payload_next.decode(FORMAT)
        payload = payload + payload_next

    payload_length = int(payload[:HEADER])
    payload = payload[HEADER:]

    while len(payload) < payload_length:
        payload_next = connection_socket.recv(1024)
        payload += payload_next.decode(FORMAT)

    current_payload = payload[:payload_length]
    payload = payload[payload_length:]
    current_payload = json.loads(current_payload)
    current_payload = speck.decrypt(current_payload)
    current_payload = json.loads(current_payload)

    return (current_payload, payload)


def save_file(file, payload, connection_socket, speck, addr):

    if not os.path.exists("data_" + name_map[addr[0]] + "/files/"):
        os.makedirs("data_" + name_map[addr[0]] + "/files/")

    file = open("data_" + name_map[addr[0]] + "/files/" + file, "wb")
    while True:

        (current_payload, payload) = receive_data(connection_socket, payload, speck)

        if current_payload == EOF:
            break

        current_payload = current_payload.encode("utf-8")
        current_payload = base64.b64decode(current_payload)
        file.write(current_payload)

    file.close()
    return payload


def send(connection_socket, data, speck):
    """sends data to the client

    Args:
        msg (string): data to send
    """
    payload = json.dumps(data)
    payload = speck.encrypt(payload)
    payload = json.dumps(payload)
    payload = f"{len(payload):<{HEADER}}" + payload
    payload = payload.encode(FORMAT)
    connection_socket.send(payload)


def send_message(connection_socket, message, speck):
    payload = {"type": MESSAGE_TYPE, "data": message}
    send(connection_socket, payload, speck)


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

    send(connection_socket, payload, speck)

    file = open(file_name, "r")
    contents = file.read(1024)
    while contents:
        send(connection_socket, contents, speck)
        contents = file.read(1024)
    file.close()
    send(connection_socket, EOF, speck)


def save_data(current_payload, addr):
    if not os.path.exists("data_" + name_map[addr[0]]):
        os.makedirs("data_" + name_map[addr[0]])

    data_file = open("data_" + name_map[addr[0]] + "/data.txt", "a+")
    data_file.write(current_payload["data"] + "\n")
    data_file.close()


def handle_client(connection_socket, addr):
    """Handles the connected clients

    Args:
        conn : connection to the client
        addr : addr of the connected client
    """
    global authenticated_keys
    key = int(shared_key[addr[0]], 16) & ((2**128) - 1)
    speck_obj = speck_using.Speck(key)

    print(f"[NEW CONNECTION] {addr} connected.")

    authenticated = False
    payload = ""
    pin = random.randint(10000, 99999)
    tries = 0

    while not authenticated:

        if tries > 2:
            print(f"[{addr}] Maximum attempts reached")
            send_message(connection_socket, DISCONNECT_MESSAGE, speck_obj)
            connection_socket.close()
            return

        (current_payload, payload) = receive_data(connection_socket, payload, speck_obj)

        if addr[0] in authenticated_keys:
            if current_payload["data"] == authenticated_keys[addr[0]]:
                authenticated = True
                send_message(
                    connection_socket,
                    AUTHENTICATED_MESSAGE,
                    speck_obj,
                )
            else:
                send_message(connection_socket, INVALID_MESSAGE, speck_obj)
                authenticated_keys.pop(addr[0])
            continue

        if addr[0] not in name_map:
            print(f"[{addr}] Please enter the pin on the device (Pin : {pin})")
        else:
            print(
                f"[{name_map[addr[0]]}] Please enter the pin on the device (Pin : {pin})"
            )

        if current_payload["data"] == pin:
            authenticated = True
            authentication_key = random.getrandbits(128)
            authenticated_keys[addr[0]] = authentication_key
            auth_file = open("server_auth.config", "w+")
            json.dump(authenticated_keys, auth_file)
            auth_file.close()
            send_message(
                connection_socket,
                AUTHENTICATED_MESSAGE,
                speck_obj,
            )
            send_message(connection_socket, authentication_key, speck_obj)
        else:
            tries += 1
            send_message(connection_socket, INVALID_MESSAGE, speck_obj)

    if addr[0] not in name_map:
        name = input(f"{addr[0]} authenticated. Give it a name : ")
        name_map[addr[0]] = name
        name_file = open("server_name.config", "w+")
        json.dump(name_map, name_file)
        name_file.close()

    clientStatusCallback(name_map, authenticated_keys, connected_clients)

    if addr[0] in send_files_set:
        send_message(connection_socket, programs_list, speck_obj)

        (current_payload, payload) = receive_data(connection_socket, payload, speck_obj)
        program_to_run = current_payload["data"]
        program_to_run = programs[program_to_run]

        send_file(
            connection_socket,
            program_to_run["program_path"],
            program_to_run["program_name"],
            speck_obj,
            False,
            False,
        )
        send_file(
            connection_socket,
            program_to_run["script_path"],
            program_to_run["script_name"],
            speck_obj,
            True,
            True,
        )
        send_files_set.remove(addr[0])

    while True:

        (current_payload, payload) = receive_data(connection_socket, payload, speck_obj)

        if not current_payload:
            print(f"[{addr} Connection closed]")
            break

        type = current_payload["type"]

        if type == MESSAGE_TYPE:
            if current_payload["data"] == DISCONNECT_MESSAGE:
                print(f"[{name_map[addr[0]]}] Disconnected")
                break
            save_data(current_payload, addr)
            print(f"[{name_map[addr[0]]}] {current_payload['data']}")
        elif type == FILE_TYPE:
            file = current_payload["file"]
            payload = save_file(file, payload, connection_socket, speck_obj, addr)
            print(f"[{name_map[addr[0]]}] {file} received")
    connection_socket.close()
    connected_clients.remove(addr[0])
    clientStatusCallback(name_map, authenticated_keys, connected_clients)


def _start_():
    """Starts the server"""
    global server, connected_clients
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(ADDR)
    lookup_thread = threading.Thread(target=lookup)
    lookup_thread.start()

    server.listen()
    print(f"[LISTENING] Server is listening on {SERVER}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        connected_clients.add(addr[0])
        # print(f"[ACTIVE CONNECTIONS] {number_of_connected_clients}")


def start(clientStatus):
    global clientStatusCallback
    clientStatusCallback = clientStatus
    server_thread = threading.Thread(target=_start_)
    server_thread.start()
    return


programs_file = open("programs.config", "r")
programs = json.load(programs_file)
programs_file.close()
programs_list = [i for i in programs]
# print("List of programs:")
# for i, a in enumerate(programs_list):
#     print(f"{i + 1}. {a}")

if os.path.exists("server_auth.config"):
    auth_file = open("server_auth.config", "r")
    authenticated_keys = json.load(auth_file)
    auth_file.close()

if os.path.exists("server_name.config"):
    name_file = open("server_name.config", "r")
    name_map = json.load(name_file)
    name_file.close()

# print("[STARTING] server is starting...")
# start()
