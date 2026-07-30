"""
===============================================================================
File: base_repository.py

Project:
SentinelDNS

Purpose:
Generic repository providing reusable CRUD operations.

Responsibilities:
- Database access only.
- No business logic.
- No transaction management.

===============================================================================
"""

from __future__ import annotations

from typing import Generic, TypeVar

from sqlalchemy import select
from sqlalchemy.orm import Session

from database.base import Base

ModelType = TypeVar("ModelType", bound=Base)


class BaseRepository(Generic[ModelType]):
    """
    Generic repository implementing reusable CRUD operations.

    NOTE:
    Transaction management (commit/rollback) belongs to the Service Layer.
    """

    def __init__(self, session: Session, model: type[ModelType]) -> None:
        self._session = session
        self._model = model

    def create(self, instance: ModelType) -> ModelType:
        """
        Add a new model instance to the current transaction.

        Does NOT commit.
        """
        self._session.add(instance)
        self._session.flush()
        return instance

    def get_by_id(self, object_id: int) -> ModelType | None:
        """
        Retrieve a model by primary key.
        """
        return self._session.get(self._model, object_id)

    def get_all(self) -> list[ModelType]:
        """
        Retrieve all records.
        """
        statement = select(self._model)
        return list(self._session.scalars(statement).all())

    def update(self, instance: ModelType) -> ModelType:
        """
        Flush pending changes.

        Does NOT commit.
        """
        self._session.flush()
        return instance

    def delete(self, instance: ModelType) -> None:
        """
        Mark an instance for deletion.

        Does NOT commit.
        """
        self._session.delete(instance)

    def exists(self, object_id: int) -> bool:
        """
        Check whether a record exists.
        """
        return self.get_by_id(object_id) is not None