from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from qnsentry.api.routers import clients, scans
from qnsentry.db.models import Base
from qnsentry.db.session import engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create missing database tables at startup."""
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="QN-Sentry API", lifespan=lifespan)
app.include_router(clients.router)
app.include_router(scans.router)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request, error: RequestValidationError
) -> JSONResponse:
    """Return validation errors as {"detail": "..."} like every other error.

    FastAPI returns a list of error objects by default, but the dashboard
    shows `detail` as text (data contract 10.5).
    """
    errors = error.errors()
    message = errors[0]["msg"] if errors else "Invalid request"
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": message.removeprefix("Value error, ")},
    )


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
