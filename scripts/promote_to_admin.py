"""Promote one existing SentinelDNS account to ADMIN.

This is a local, filesystem-level bootstrap utility. It is intentionally
not exposed as a web/API endpoint.
"""

from __future__ import annotations

import sys

from database.database import SessionLocal
from database.enums.user_role import UserRole
from database.models.user import User


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1].strip():
        print("Usage: python scripts\\promote_to_admin.py <username>")
        return 2

    username = sys.argv[1].strip()
    db = SessionLocal()

    try:
        user = db.query(User).filter(User.username == username).first()

        if user is None:
            print("ERROR: User account was not found.")
            return 1

        if user.role == UserRole.ADMIN:
            print("OK: Account is already ADMIN.")
            return 0

        user.role = UserRole.ADMIN
        db.commit()
        print("OK: Account promoted to ADMIN.")
        print(f"Username: {user.username}")
        return 0
    except Exception as exc:
        db.rollback()
        print(f"ERROR: Could not update the account: {exc}")
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
