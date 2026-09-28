"""Shared FastAPI dependencies: how route handlers get the database and secret box.

Both live on app.state, set once in api.app.create_app(). Handlers receive
them through these dependencies instead of importing globals, so a test can
build an app around a throwaway data directory and every route just works.
"""

from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.engine import Engine

from heron.core.crypto import SecretBox


def get_engine(request: Request) -> Engine:
    return request.app.state.engine


def get_secret_box(request: Request) -> SecretBox:
    return request.app.state.secret_box


EngineDep = Annotated[Engine, Depends(get_engine)]
SecretBoxDep = Annotated[SecretBox, Depends(get_secret_box)]
