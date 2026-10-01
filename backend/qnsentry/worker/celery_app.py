from celery import Celery
from celery.schedules import crontab

from qnsentry.config import settings

celery_app = Celery(
    "qnsentry",
    broker=settings.redis_url,
    include=["qnsentry.worker.tasks", "qnsentry.worker.retention"],
)

celery_app.conf.update(
    # Acknowledge a task only when it is finished, so a crashed worker
    # does not lose the scan it was running
    task_acks_late=True,
    # Scans are long: take one task at a time instead of reserving several
    worker_prefetch_multiplier=1,
    # Redis hands an unacknowledged task to another worker after this many seconds.
    # Keep it above the longest scan, or a long scan would run twice at the same time.
    broker_transport_options={
        "visibility_timeout": (settings.scan_timeout_minutes + 60) * 60
    },
    # Periodic tasks, started by the "beat" service in docker-compose.yml
    beat_schedule={
        # GDPR storage limitation (#46): once a day, at night
        "delete-expired-scans": {
            "task": "qnsentry.worker.retention.delete_expired_scans",
            "schedule": crontab(hour=3, minute=0),
        },
    },
    timezone="UTC",
)
