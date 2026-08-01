import socket

query = bytes.fromhex(
    "12340100000100000000000006676f6f676c6503636f6d0000010001"
)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)

sock.sendto(query, ("127.0.0.1", 5353))

response, _ = sock.recvfrom(4096)

print("Received", len(response), "bytes")
print(response.hex())