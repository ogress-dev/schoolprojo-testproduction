from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
from enum import Enum

class Classification(str, Enum):
    BENIGN = "benign"
    DEFACEMENT = "defacement"
    MALWARE = "malware"
    PHISHING = "phishing"

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class URLScanBase(BaseModel):
    url: str
    classification: Classification
    confidence: int
    risk_score: int

class URLScan(URLScanBase):
    id: str
    scanned_at: datetime
    created_at: datetime

class URLScanCreate(URLScanBase):
    pass

class ScanFeatureBase(BaseModel):
    feature_name: str
    feature_value: float
    importance: float
    is_risk_factor: bool

class ScanFeature(ScanFeatureBase):
    id: str
    scan_id: str

class ScanFeatureCreate(ScanFeatureBase):
    pass

class RiskFactorBase(BaseModel):
    factor_name: str
    severity: Severity
    description: str

class RiskFactor(RiskFactorBase):
    id: str
    scan_id: str

class RiskFactorCreate(RiskFactorBase):
    pass

class SecurityRecommendation(BaseModel):
    title: str
    description: str
    priority: Severity

class ClassificationResult(BaseModel):
    classification: Classification
    confidence: int
    risk_score: int
    features: List[ScanFeatureCreate]
    risk_factors: List[RiskFactorCreate]
    recommendations: List[SecurityRecommendation]

class DetailedScan(URLScan):
    features: List[ScanFeature]
    risk_factors: List[RiskFactor]

class ClassificationStats(BaseModel):
    benign: int
    defacement: int
    malware: int
    phishing: int
    total: int