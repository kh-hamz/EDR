import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI

from .api import alerts, detection, events, hosts, ingest
from .core.db import Base, engine
from .detection.engine import run_detection
from .storage.opensearch_client import ensure_index_template

log = logging.getLogger(__name__)

DETECTION_INTERVAL_SECONDS = 30


async def _detection_loop():
    last_run = datetime.now(timezone.utc)
    while True:
        await asyncio.sleep(DETECTION_INTERVAL_SECONDS)
        now = datetime.now(timezone.utc)
        try:
            created = await asyncio.to_thread(run_detection, last_run)
            if created:
                log.info("detection run: %d new alert(s)", created)
        except Exception:
            log.exception("detection run failed")
        last_run = now


@asynccontextmanager
async def lifespan(app: FastAPI):
    # SQLAlchemy create_all is fine while the schema is young; a real
    # migration tool (alembic) becomes worth it once tables start changing.
    Base.metadata.create_all(engine)
    ensure_index_template()
    task = asyncio.create_task(_detection_loop())
    yield
    task.cancel()


app = FastAPI(title="EDR Backend", lifespan=lifespan)
app.include_router(ingest.router)
app.include_router(hosts.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(detection.router)


@app.get("/health")
def health():
    return {"status": "ok"}
