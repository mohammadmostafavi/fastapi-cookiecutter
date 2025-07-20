from sqlalchemy import Column, Integer, String, DateTime, func
from src.core.models import Base

class Log(Base):
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True)
    action = Column(String(255))
    timestamp = Column(DateTime, server_default=func.now())
