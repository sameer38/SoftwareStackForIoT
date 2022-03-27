import client
import time
import random

client2 = client.client(False)


# Generate 5 random rumbers and send them to the server
for i in range(5):
    client2.send(str(random.randint(1, 100)))
    time.sleep(0.5)

# Disconnect from the server
client2.send(client2.DISCONNECT_MESSAGE)
