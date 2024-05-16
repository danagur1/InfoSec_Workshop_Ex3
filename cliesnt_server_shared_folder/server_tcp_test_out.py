import socket

# Define the listening IP and port
listening_ip = '0.0.0.0'   # Listen on all available interfaces
listening_port = 12345      # Choose a port number to listen on

# Create a TCP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the listening IP and port
server_socket.bind((listening_ip, listening_port))

# Start listening for incoming connections
server_socket.listen(1)  # Listen for only one connection

print("Server is listening on {}:{}".format(listening_ip, listening_port))

# Accept incoming connection
client_socket, client_address = server_socket.accept()
print("Connection accepted from:", client_address)

# Receive data
received_data = client_socket.recv(1024)
print("Received data:", received_data.decode())

# Send ACK
ack_message = b"ACK"
client_socket.sendall(ack_message)

# Close the connection
client_socket.close()
server_socket.close()
