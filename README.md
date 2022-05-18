# SoftwareStackForIoT
This is the repo for BTP project Software Stack for IoT devices.

# Instructions

1. Compile [speck.c](./simon_and_speck/speck.c) using the following command.
``
gcc -shared -fPIC -o libspeck.so speck.c 
``
2. Place the libspeck.so file obtained in [server](./server) and [client](./client) folders for server and client the respectively.
3. To run the server use the following command 
``
cd server
``
``
python3 gui.py
``
4. To run the client use the following command
``
cd client
``
``
python3 client.py
``

# Dependencies
1. pyDH - ``pip install pyDH``
2. pyQT5 - ``pip install pyQt5``
