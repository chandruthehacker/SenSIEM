import os
from sqlalchemy import (
    BigInteger, create_engine, Column, Integer, String, Text, DateTime, ForeignKey, Boolean, JSON
)
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime

# Setup DB Path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, '..', '..', 'database', "sensiem.db")
DATABASE_URI = f"sqlite:///{DATABASE_PATH}"

# SQLAlchemy Setup
Base = declarative_base()
engine = create_engine(DATABASE_URI, echo=False)
Session = sessionmaker(bind=engine)

class ParsedLog(Base):
    __tablename__ = "parsed_logs"

    id = Column(Integer, primary_key=True)

    # Core Fields
    timestamp = Column(DateTime)
    log_level = Column(String(20))
    source = Column(String(100))
    host = Column(String(100))
    process = Column(String(100))
    message = Column(Text)
    raw_log = Column(Text)
    type = Column(String(50))
    file_path = Column(String(255))
    source_id = Column(Integer, ForeignKey("log_sources.id"))

    # Extended Metadata Fields
    event_id = Column(String(50), nullable=True)
    username = Column(String(100), nullable=True)
    status_code = Column(String(10), nullable=True)
    url = Column(String(2048), nullable=True)
    method = Column(String(10), nullable=True)
    protocol = Column(String(20), nullable=True)
    src_ip = Column(String(100), nullable=True)
    dest_ip = Column(String(100), nullable=True)
    src_port = Column(String(10), nullable=True)
    dest_port = Column(String(10), nullable=True)
    rule = Column(String(255), nullable=True)
    signature = Column(String(255), nullable=True)
    action = Column(String(50), nullable=True)
    user_agent = Column(String(512), nullable=True)
    device = Column(String(100), nullable=True)
    mail_subject = Column(String(255), nullable=True)
    file_hash = Column(String(128), nullable=True)
    tags = Column(String(255), nullable=True)
    alert = Column(Integer, default=0)
    
    source_rel = relationship("LogSource", back_populates="logs")


# 2. Log Sources
class LogSource(Base):
    __tablename__ = "log_sources"
    id = Column(Integer, primary_key=True)
    name = Column(String(100))
    path = Column(String(255))
    log_type = Column(String(50))  # e.g., syslog, firewall, etc.
    added_on = Column(DateTime, default=datetime.utcnow)
    active = Column(Boolean, default=True)
    source_tag = Column(String(100))  # Optional alias
    last_position = Column(Text, default='0')
    
    logs = relationship("ParsedLog", back_populates="source_rel")

# 3. Detection Rules
class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id = Column(Integer, primary_key=True)
    name = Column(String(100))
    description = Column(Text)
    rule_type = Column(String(50))  # e.g., threshold, pattern, anomaly
    log_type = Column(String(50))
    condition = Column(Text)  # Rule condition as string
    threshold = Column(Integer)
    time_window = Column(Integer)  # seconds
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

# 4. Alerts
class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)

    rule_type = Column(String(100), nullable=False)         # e.g., "Brute Force", "Anomaly", etc.

    log_id = Column(Integer, ForeignKey("parsed_logs.id"))

    alert_time = Column(DateTime, default=datetime.utcnow)
    severity = Column(String(20), nullable=False)
    message = Column(Text, nullable=False)
    status = Column(String(20), default="new")

    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    ip = Column(String(45), nullable=True)
    host = Column(String(255), nullable=True)
    source = Column(String(255), nullable=True)

    log = relationship("ParsedLog", back_populates="alerts")

# 5. Saved Queries
class SavedQuery(Base):
    __tablename__ = "saved_queries"
    id = Column(Integer, primary_key=True)
    name = Column(String(100))
    query_string = Column(Text)
    created_by = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow)

# 6. Ingested Files
class IngestFile(Base):
    __tablename__ = "ingest_files"
    id = Column(Integer, primary_key=True)
    filename = Column(String(255))
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    file_path = Column(String(255))
    log_type = Column(String(50))
    size_bytes = Column(Integer)
    source_id = Column(Integer, ForeignKey("log_sources.id"))

# 7. Users (Optional)
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True)
    email = Column(String(150), unique=True)
    password_hash = Column(String(255))
    role = Column(String(50))  # admin, analyst
    created_at = Column(DateTime, default=datetime.utcnow)

# Create All Tables
def create_tables():
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    Base.metadata.create_all(engine)
    print("✅ All SenSIEM tables created successfully.")

if __name__ == '__main__':
    create_tables()