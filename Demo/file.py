from time import sleep
import client


client2 = client.client(False)


# Generate 5 random rumbers and send them to the server

sleep(2)
print("Sending ....")
client2.send_file("./libspeck.so", "libspeck.so")
print("Sent")

# Disconnect from the server
client2.send(client2.DISCONNECT_MESSAGE)
