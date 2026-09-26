from celery import Celery

from qnsentry.config import settings

celery_app = Celery(
    "qnsentry",
    broker=settings.redis_url,
    include=["qnsentry.worker.tasks"],
)

celery_app.conf.update(
    # Acknowledge a task only when it is finished, so a crashed worker
    # does not lose the scan it was running
    task_acks_late=True,
    # Scans are long: take one task at a time instead of reserving several
    worker_prefetch_multiplier=1,
)
