from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
import datetime

Base = declarative_base()

class URLScanDB(Base):
    __tablename__ = "url_scans"

    id = Column(String, primary_key=True)
    url = Column(String, nullable=False)
    classification = Column(String, nullable=False)
    confidence = Column(Integer, nullable=False)
    risk_score = Column(Integer, nullable=False)
    scanned_at = Column(DateTime, default=datetime.datetime.utcnow)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    features = relationship("ScanFeatureDB", back_populates="scan")
    risk_factors = relationship("RiskFactorDB", back_populates="scan")

class ScanFeatureDB(Base):
    __tablename__ = "scan_features"

    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("url_scans.id"), nullable=False)
    feature_name = Column(String, nullable=False)
    feature_value = Column(Float, nullable=False)
    importance = Column(Float, nullable=False)
    is_risk_factor = Column(Boolean, nullable=False)

    scan = relationship("URLScanDB", back_populates="features")

class RiskFactorDB(Base):
    __tablename__ = "risk_factors"

    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("url_scans.id"), nullable=False)
    factor_name = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    description = Column(String, nullable=False)

    scan = relationship("URLScanDB", back_populates="risk_factors")

# Database setup
DATABASE_URL = "sqlite:///./url_scanner.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def create_tables():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()