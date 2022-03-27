# from picamera import PiCamera
from time import sleep
import client

# camera = PiCamera()


client2 = client.client(False)


# # Generate 5 random rumbers and send them to the server
# for i in range(1, 3):
#     # camera.start_preview()
#     sleep(2)
#     # camera.capture("/home/pi/image" + i + ".png")
#     # camera.stop_preview()
client2.send_file("./test.png", "pi_test.png")
sleep(2)
client2.send_file("./test2.png", "pi_test2.png")


# Disconnect from the server
client2.send(client2.DISCONNECT_MESSAGE)
