import os
from . import database
"""
Celery configuration constants.

This module contains constants related to Celery configuration and operations.
"""

CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "db+postgresql://username:password@localhost:5432/celery_results")
CELERY_CACHE_BACKEND = os.getenv("CELERY_CACHE_BACKEND", "redis://localhost:6379/0")
CELERY_TASK_ALWAYS_EAGER = (
    os.getenv("CELERY_TASK_ALWAYS_EAGER", "False").lower() == "true"
)
CELERY_TASK_EAGER_PROPAGATES = (
    os.getenv("CELERY_TASK_EAGER_PROPAGATES", "False").lower() == "true"
)
CELERY_TASK_SERIALIZER = os.getenv("CELERY_TASK_SERIALIZER", "json")
CELERY_RESULT_SERIALIZER = os.getenv("CELERY_RESULT_SERIALIZER", "json")
CELERY_ACCEPT_CONTENT = os.getenv("CELERY_ACCEPT_CONTENT", "json").split(",")