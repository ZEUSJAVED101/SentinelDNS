from backend.security.jwt import create_access_token, decode_access_token

token = create_access_token("zeeshan")

print("TOKEN:")
print(token)

print("\nPAYLOAD:")
print(decode_access_token(token))