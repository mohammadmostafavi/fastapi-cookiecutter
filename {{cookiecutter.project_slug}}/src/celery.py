"""
Celery application configuration.

This module initializes and configures the Celery application for the project.
It sets up the Celery instance, configures it using the settings from config.py,
and defines the Celery Beat schedule.
"""

import os
from celery import Celery
from celery.schedules import crontab
from src.config import settings

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('CELERY_CONFIG_MODULE', 'src.config')

# Create the Celery application
celery_app = Celery(
    settings.project_name,
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

# Configure Celery using the settings from config.py
celery_app.conf.update(
    task_serializer=settings.celery_task_serializer,
    result_serializer=settings.celery_result_serializer,
    accept_content=settings.celery_accept_content,
    task_always_eager=settings.celery_task_always_eager,
    worker_hijack_root_logger=False,
    timezone='UTC',
    enable_utc=True,
)

# Configure Celery Beat schedule
celery_app.conf.beat_schedule = {
    # 'example-task-every-minute': {
    #     'task': 'src.apps.example.tasks.example_periodic_task',
    #     'schedule': crontab(minute='*'),  # Run every minute
    #     'args': (),
    # },
}

# Auto-discover tasks in all installed apps
celery_app.autodiscover_tasks()