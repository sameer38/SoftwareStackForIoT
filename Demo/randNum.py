from client import connect, send, DISCONNECT_MESSAGE
import time
import random

# Connect to the server
connect()

# Generate 5 random rumbers and send them to the server
for i in range(5):
    send(str(random.randint(1, 100)))
    time.sleep(0.5)

# Disconnect from the server
send(DISCONNECT_MESSAGE)