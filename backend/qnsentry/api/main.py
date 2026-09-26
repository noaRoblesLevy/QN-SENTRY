from fastapi import FastAPI

app = FastAPI(title="QN-Sentry API")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}