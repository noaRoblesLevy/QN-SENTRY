from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from qnsentry.db.session import engine

app = FastAPI(title="QN-Sentry API")


@app.get("/api/health")
def health() -> JSONResponse:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except OperationalError:
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "database": "unavailable"},
        )
    return JSONResponse(content={"status": "ok", "database": "ok"})
