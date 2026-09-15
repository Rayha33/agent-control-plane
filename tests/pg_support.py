"""Scratch PostgreSQL schemas for tests that need a live server (board #568).

Each test gets its own schema through ``search_path``, so tests cannot see each other's rows
and the backend's advisory write lock (keyed by database + schema) does not couple them.
Point ACP_TEST_POSTGRES_URL at a disposable server; never at a database anything else uses.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import quote


def schema_url(base_url: str, schema: str) -> str:
    separator = "&" if "?" in base_url else "?"
    return f"{base_url}{separator}options={quote(f'-c search_path={schema}')}"


@contextmanager
def postgres_schema(base_url: str) -> Iterator[str]:
    import psycopg

    schema = f"acp_test_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(base_url, autocommit=True) as connection:
        connection.execute(f'CREATE SCHEMA "{schema}"')
    try:
        yield schema_url(base_url, schema)
    finally:
        with psycopg.connect(base_url, autocommit=True) as connection:
            connection.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
