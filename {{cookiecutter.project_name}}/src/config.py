import os
from typing import List, Optional

from pydantic_settings import BaseSettings
from src.constants import app, database, celery, csp, cors, auth


class Settings(BaseSettings):
    """
    Application settings.

    This class contains all the configuration settings for the application.
    Values are loaded from environment variables or use the provided defaults.
    """

    # Database settings
    db_url: str = database.DB_URL
    echo_sql: bool = True

    # Application settings
    project_name: str = app.APP_NAME
    debug: bool = app.DEBUG
    test: bool = False

    # Authentication settings
    oauth_token_secret: str = auth.OAUTH_TOKEN_SECRET
    jwt_algorithm: str = auth.JWT_ALGORITHM

    # Celery settings
    celery_broker_url: str = celery.CELERY_BROKER_URL
    celery_result_backend: str = celery.CELERY_RESULT_BACKEND
    celery_task_always_eager: bool = celery.CELERY_TASK_ALWAYS_EAGER
    celery_task_serializer: str = celery.CELERY_TASK_SERIALIZER
    celery_result_serializer: str = celery.CELERY_RESULT_SERIALIZER
    celery_accept_content: List[str] = celery.CELERY_ACCEPT_CONTENT

    # CORS settings
    cors_allow_origins: List[str] = cors.CORS_ALLOW_ORIGINS
    cors_allow_credentials: bool = cors.CORS_ALLOW_CREDENTIALS
    cors_allow_methods: List[str] = cors.CORS_ALLOW_METHODS
    cors_allow_headers: List[str] = cors.CORS_ALLOW_HEADERS
    cors_expose_headers: List[str] = cors.CORS_EXPOSE_HEADERS
    cors_max_age: int = cors.CORS_MAX_AGE

    # Content Security Policy settings
    csp_enabled: bool = csp.CSP_ENABLED
    csp_default_src: List[str] = csp.CSP_DEFAULT_SRC
    csp_script_src: List[str] = csp.CSP_SCRIPT_SRC
    csp_style_src: List[str] = csp.CSP_STYLE_SRC
    csp_img_src: List[str] = csp.CSP_IMG_SRC
    csp_connect_src: List[str] = csp.CSP_CONNECT_SRC
    csp_font_src: List[str] = csp.CSP_FONT_SRC
    csp_object_src: List[str] = csp.CSP_OBJECT_SRC
    csp_media_src: List[str] = csp.CSP_MEDIA_SRC
    csp_frame_src: List[str] = csp.CSP_FRAME_SRC
    csp_report_uri: str = csp.CSP_REPORT_URI


settings = Settings()  # type: ignore
