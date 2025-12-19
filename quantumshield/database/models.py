"""Database models using SQLAlchemy."""

from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()


class Alert(Base):
    """Security alert model."""
    
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src_ip = Column(String(45))
    dst_ip = Column(String(45))
    threat_score = Column(Float)
    action = Column(String(50))
    reason = Column(Text)
    severity = Column(String(20))


class TrafficLog(Base):
    """Traffic log model."""
    
    __tablename__ = "traffic_logs"
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    src_ip = Column(String(45))
    dst_ip = Column(String(45))
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(Integer)
    length = Column(Integer)
    action = Column(String(50))

