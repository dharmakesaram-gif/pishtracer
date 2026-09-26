from sqlalchemy import Column, String, Integer, Float, DateTime, Text
from datetime import datetime
from uuid import uuid4
from database.database import Base

class ScanResult(Base):
    __tablename__ = 'scan_results'
    
    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow)
    sender_name = Column(String, nullable=True)
    sender_email = Column(String, nullable=True)
    sender_domain = Column(String, nullable=True)
    subject = Column(String, nullable=True)
    body_snippet = Column(Text, nullable=True)  # first 500 chars
    risk_score = Column(Integer, default=0)
    risk_level = Column(String, default='LOW')  # LOW, MEDIUM, HIGH, CRITICAL
    reasons = Column(Text, nullable=True)  # JSON array
    
    # Header forensics
    from_domain = Column(String, nullable=True)
    return_path_domain = Column(String, nullable=True)
    spf_result = Column(String, nullable=True)
    dkim_result = Column(String, nullable=True)
    dmarc_result = Column(String, nullable=True)
    
    # Geo data
    origin_ip = Column(String, nullable=True)
    geo_country = Column(String, nullable=True)
    geo_city = Column(String, nullable=True)
    geo_lat = Column(Float, nullable=True)
    geo_lon = Column(Float, nullable=True)
    asn = Column(String, nullable=True)
    infra_type = Column(String, nullable=True)  # RESIDENTIAL, DATACENTER, VPN, TOR
    abuse_score = Column(Integer, nullable=True)
    
    # Campaign
    campaign_id = Column(String, nullable=True)
    evidence_hash = Column(String, nullable=True)  # SHA-256 of all evidence


class Campaign(Base):
    __tablename__ = 'campaigns'
    
    id = Column(String, primary_key=True, default=lambda: str(uuid4()))
    name = Column(String)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    scan_count = Column(Integer, default=1)
    domains = Column(Text, nullable=True)  # JSON array
    ips = Column(Text, nullable=True)  # JSON array
    risk_level = Column(String, default='MEDIUM')
