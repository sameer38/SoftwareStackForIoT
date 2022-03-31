from picamera import PiCamera
from time import sleep
import client

camera = PiCamera()
# camera.resolution = (64, 64)

client2 = client.client(False)


# Generate 5 random rumbers and send them to the server
for i in range(1, 3):
    camera.start_preview()
    # sleep(5)
    print("Capturing ....")
    camera.capture("./image" + str(i) + ".png")
    camera.stop_preview()
    print("Sending ....")
    client2.send_file("./image" + str(i) + ".png", "./image" + str(i) + ".png")
    print("Sent")

# Disconnect from the server
client2.send(client2.DISCONNECT_MESSAGE)
