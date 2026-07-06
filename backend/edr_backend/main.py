from contextlib import asynccontextmanager

from fastapi import FastAPI

from .api import hosts, ingest
from .core.db import Base, engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    # SQLAlchemy create_all is fine while the schema is young; a real
    # migration tool (alembic) becomes worth it once tables start changing.
    Base.metadata.create_all(engine)
    yield


app = FastAPI(title="EDR Backend", lifespan=lifespan)
app.include_router(ingest.router)
app.include_router(hosts.router)


@app.get("/health")
def health():
    return {"status": "ok"}
