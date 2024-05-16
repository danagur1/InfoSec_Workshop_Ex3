import socket

# Define the target IP and port
target_ip = '127.0.0.1'  # Replace with your target IP address
target_port = 12345       # Replace with your target port number

# Create a TCP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server
client_socket.connect((target_ip, target_port))

# Send data
data = b"Hello, server!"
client_socket.sendall(data)

# Close the connection
client_socket.close()
