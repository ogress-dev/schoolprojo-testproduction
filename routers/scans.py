from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
import uuid
from datetime import datetime

from database import get_db, URLScanDB, ScanFeatureDB, RiskFactorDB
from models import (
    URLScan,
    URLScanCreate,
    DetailedScan,
    ClassificationStats,
    ClassificationResult,
    Classification,
    Severity,
    RiskFactorCreate
)
from classifier import URLClassifier

router = APIRouter()

@router.post("/scan", response_model=ClassificationResult)
async def scan_url(url: str):
    """Scan a URL and return classification results"""
    try:
        result = URLClassifier.classify_url(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error scanning URL: {str(e)}")

@router.post("/scan/save", response_model=str)
async def scan_and_save_url(
    url: str,
    db: Session = Depends(get_db)
):
    """Scan a URL, save results to database, and return scan ID"""
    try:
        result = URLClassifier.classify_url(url)

        # Generate scan ID
        scan_id = str(uuid.uuid4())

        # Create scan record
        scan_db = URLScanDB(
            id=scan_id,
            url=url,
            classification=result.classification.value,
            confidence=result.confidence,
            risk_score=result.risk_score,
            scanned_at=datetime.utcnow()
        )

        db.add(scan_db)

        # Add features
        for feature in result.features:
            feature_db = ScanFeatureDB(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                feature_name=feature.feature_name,
                feature_value=feature.feature_value,
                importance=feature.importance,
                is_risk_factor=feature.is_risk_factor
            )
            db.add(feature_db)

        # Add risk factors
        for risk_factor in result.risk_factors:
            risk_factor_db = RiskFactorDB(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                factor_name=risk_factor.factor_name,
                severity=risk_factor.severity.value,
                description=risk_factor.description
            )
            db.add(risk_factor_db)

        db.commit()
        return scan_id

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error saving scan: {str(e)}")

@router.get("/scans", response_model=List[URLScan])
async def get_all_scans(db: Session = Depends(get_db)):
    """Get all scans"""
    try:
        scans = db.query(URLScanDB).order_by(URLScanDB.scanned_at.desc()).all()
        return [
            URLScan(
                id=str(scan.id),
                url=str(scan.url),
                classification=Classification(scan.classification),
                confidence=int(scan.confidence),
                risk_score=int(scan.risk_score),
                scanned_at=scan.scanned_at.isoformat(),
                created_at=scan.created_at.isoformat()
            )
            for scan in scans
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching scans: {str(e)}")

@router.get("/scans/{scan_id}", response_model=DetailedScan)
async def get_scan_by_id(scan_id: str, db: Session = Depends(get_db)):
    """Get detailed scan by ID"""
    try:
        scan = db.query(URLScanDB).filter(URLScanDB.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        features = db.query(ScanFeatureDB).filter(ScanFeatureDB.scan_id == scan_id).all()
        risk_factors = db.query(RiskFactorDB).filter(RiskFactorDB.scan_id == scan_id).all()

        risk_factors_data = [
            {
                "id": rf.id,
                "scan_id": rf.scan_id,
                "factor_name": rf.factor_name,
                "severity": rf.severity,
                "description": rf.description
            }
            for rf in risk_factors
        ]

        # Generate recommendations
        recommendations = URLClassifier.generate_recommendations(
            Classification(scan.classification),
            [
                RiskFactorCreate(
                    factor_name=rf["factor_name"],
                    severity=Severity(rf["severity"]),
                    description=rf["description"]
                )
                for rf in risk_factors_data
            ]
        )

        return DetailedScan(
            id=str(scan.id),
            url=str(scan.url),
            classification=Classification(scan.classification),
            confidence=int(scan.confidence),
            risk_score=int(scan.risk_score),
            scanned_at=scan.scanned_at.isoformat(),
            created_at=scan.created_at.isoformat(),
            features=[
                {
                    "id": str(f.id),
                    "scan_id": str(f.scan_id),
                    "feature_name": str(f.feature_name),
                    "feature_value": float(f.feature_value),
                    "importance": float(f.importance),
                    "is_risk_factor": bool(f.is_risk_factor)
                }
                for f in features
            ],
            risk_factors=risk_factors_data,
            recommendations=[rec.dict() for rec in recommendations]
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching scan: {str(e)}")

@router.get("/statistics", response_model=ClassificationStats)
async def get_statistics(db: Session = Depends(get_db)):
    """Get classification statistics"""
    try:
        scans = db.query(URLScanDB).all()

        stats = {
            "benign": 0,
            "defacement": 0,
            "malware": 0,
            "phishing": 0,
            "total": len(scans)
        }

        for scan in scans:
            classification = scan.classification
            if classification in stats:
                stats[classification] += 1

        return ClassificationStats(**stats)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching statistics: {str(e)}")

@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    """Delete a scan by ID"""
    try:
        scan = db.query(URLScanDB).filter(URLScanDB.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        db.delete(scan)
        db.commit()
        return {"message": "Scan deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error deleting scan: {str(e)}")