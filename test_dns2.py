import socket

SERVER = "127.0.0.1"
PORT = 5300

# Standard DNS query for google.com (A record)
QUERY = bytes.fromhex(
    "123401000001000000000000"
    "06676f6f676c6503636f6d00"
    "00010001"
)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)

print(f"Sending DNS query to {SERVER}:{PORT}...")

sock.sendto(QUERY, (SERVER, PORT))

try:
    response, addr = sock.recvfrom(4096)

    print(f"\nResponse received from {addr}")
    print(f"Response length : {len(response)} bytes")
    print(f"Transaction ID  : {response[:2].hex()}")
    print(f"Flags           : {response[2:4].hex()}")
    print(f"Raw Response    : {response.hex()}")

except socket.timeout:
    print("\n❌ Request timed out.")

finally:
    sock.close()