#    Copyright 2025 FAO
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
#    Author: Carlo Cancellieri (ccancellieri@gmail.com)
#    Company: FAO, Viale delle Terme di Caracalla, 00100 Rome, Italy
#    Contact: copyright@fao.org - http://fao.org/contact-us/terms/en/

import json
import typing
from datetime import datetime

from starlette_session.backends.base import Backend


class DatabaseBackend(Backend):
    """
    A server-side session backend for starlette-session that uses a SQLAlchemy
    database table for storage.
    """

    def __init__(
        self,
        session_table: "DeclarativeMeta",
        db_callable: typing.Callable[[], typing.AsyncContextManager],
    ):
        """
        Initialize the DatabaseBackend.

        Args:
            session_table: The SQLAlchemy model class for storing session data.
            db_callable: An async context manager that yields a SQLAlchemy async session.
        """
        try:
            from sqlalchemy import select, delete
        except ImportError:
            raise ImportError(
                "SQLAlchemy is required for DatabaseBackend. "
                "Install it with `pip install SQLAlchemy`."
            )

        self.session_table = session_table
        self.db_callable = db_callable
        self._select = select
        self._delete = delete

    async def read(self, session_id: str) -> typing.Dict:
        async with self.db_callable() as db:
            stmt = self._select(self.session_table.data).where(
                self.session_table.session_id == session_id
            )
            result = await db.execute(stmt)
            data = result.scalar_one_or_none()
            return json.loads(data) if data else {}

    async def write(self, session_id: str, data: typing.Dict, last_modified: datetime) -> None:
        async with self.db_callable() as db:
            # merge() checks the primary key; if it exists in the session/DB, it updates,
            # otherwise it inserts. This is more robust than explicit check-then-insert.
            session_obj = self.session_table(
                session_id=session_id, 
                data=json.dumps(data), 
                last_modified=last_modified
            )
            await db.merge(session_obj)
            await db.commit()

    async def remove(self, session_id: str) -> None:
        async with self.db_callable() as db:
            stmt = self._delete(self.session_table).where(self.session_table.session_id == session_id)
            await db.execute(stmt)
            await db.commit()

    async def exists(self, session_id: str) -> bool:
        async with self.db_callable() as db:
            stmt = self._select(self.session_table.session_id).where(self.session_table.session_id == session_id)
            result = await db.execute(stmt)
            return result.scalar_one_or_none() is not None