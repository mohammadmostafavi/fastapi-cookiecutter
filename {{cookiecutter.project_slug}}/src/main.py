import sys
import uvicorn
import logging
from src.config import settings
from typing import AsyncGenerator
from fastapi import FastAPI, APIRouter
from contextlib import asynccontextmanager
from src.apps.auth.routes import auth_router
from src.database import sessionmanager
from src.middleware.register import register_middleware
from src.health import health_router
from src.constants.app import (
    API_PREFIX,
    API_V1_PREFIX,
    LOG_FORMAT,
    LOG_DATE_FORMAT,
)
from dotenv import load_dotenv


logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG if settings.debug else logging.INFO,
    format=LOG_FORMAT,
    datefmt=LOG_DATE_FORMAT,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    # Load environment variables
    load_dotenv()
    # Connect to the database
    await sessionmanager.connect()

    # Register in the dependency container

    # Log application startup
    logging.info(f"Application {settings.project_name} started")

    yield

    # Clean up resources
    if sessionmanager._engine is not None:
        # Close the DB connection
        await sessionmanager.close()
        logging.info("Database connection closed")


app = FastAPI(lifespan=lifespan, title=settings.project_name, debug=settings.debug)
api_router = APIRouter()
api_v1_router = APIRouter()

# Register all middleware
register_middleware(app)

# Include routers
api_router.include_router(auth_router, prefix="/auth", tags=["auth"])
api_v1_router.include_router(api_router, prefix=API_V1_PREFIX)
app.include_router(api_v1_router, prefix=API_PREFIX)

# Include health check router at the root level
app.include_router(health_router)


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", reload=settings.debug, port=8000)
