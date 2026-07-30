from backend.schemas.user import UserCreate
from backend.schemas.auth import LoginRequest
from backend.services.authentication_service import AuthenticationService
from database.database import SessionLocal

db = SessionLocal()

service = AuthenticationService(db)

try:
    user = service.register(
        UserCreate(
            username="zeeshan",
            email="zeeshan@example.com",
            password="Password123!"
        )
    )

    print("REGISTERED:")
    print(user)

except Exception as exc:
    print(exc)

try:
    token = service.authenticate(
        LoginRequest(
            username="zeeshan",
            password="Password123!"
        )
    )

    print("\nTOKEN:")
    print(token)

except Exception as exc:
    print(exc)

db.close()