import re
import random
from typing import List
from models import (
    Classification,
    Severity,
    ScanFeatureCreate,
    RiskFactorCreate,
    SecurityRecommendation,
    ClassificationResult
)
from model_loader import model_loader

class URLClassifier:
    @staticmethod
    def classify_url(url: str) -> ClassificationResult:
        # Simulate processing time (optional)
        import time
        time.sleep(1.5)

        # Use ML models for prediction
        predicted_class, ml_confidence = model_loader.predict_url(url)
        
        # Convert string prediction to Classification enum
        classification_map = {
            'benign': Classification.BENIGN,
            'defacement': Classification.DEFACEMENT,
            'malware': Classification.MALWARE,
            'phishing': Classification.PHISHING
        }
        classification = classification_map.get(predicted_class.lower(), Classification.BENIGN)
        
        # Get class probabilities for additional insights
        class_probabilities = model_loader.get_class_probabilities(url)
        
        # Extract features using ML model
        ml_features = URLClassifier.extract_ml_features(url, class_probabilities)
        
        # Calculate risk score based on ML prediction
        risk_score = URLClassifier.calculate_ml_risk_score(class_probabilities, classification)
        
        # Convert ML confidence (0-1) to percentage (0-100)
        confidence = int(ml_confidence * 100)
        
        # Identify risk factors based on ML prediction
        risk_factors = URLClassifier.identify_ml_risk_factors(url, classification, class_probabilities)
        
        # Generate recommendations based on ML classification
        recommendations = URLClassifier.generate_ml_recommendations(classification, risk_factors, class_probabilities)

        return ClassificationResult(
            classification=classification,
            confidence=confidence,
            risk_score=risk_score,
            features=ml_features,
            risk_factors=risk_factors,
            recommendations=recommendations
        )

    @staticmethod
    def extract_features(url: str) -> List[ScanFeatureCreate]:
        url_length = len(url)
        has_suspicious_chars = bool(re.search(r'[<>{}[\]\\|^~`]', url))
        has_ip_address = bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))
        has_multiple_subdomains = len(re.findall(r'\.', url)) > 3
        has_https = url.startswith('https://')
        has_port = bool(re.search(r':\d+', url))
        has_suspicious_keywords = bool(re.search(r'login|secure|account|verify|update|confirm', url, re.IGNORECASE))
        number_of_dashes = len(re.findall(r'-', url))

        features = [
            ScanFeatureCreate(
                feature_name='URL Length',
                feature_value=url_length,
                importance=0.15,
                is_risk_factor=url_length > 75
            ),
            ScanFeatureCreate(
                feature_name='Has HTTPS',
                feature_value=1.0 if has_https else 0.0,
                importance=0.25,
                is_risk_factor=not has_https
            ),
            ScanFeatureCreate(
                feature_name='Suspicious Characters',
                feature_value=1.0 if has_suspicious_chars else 0.0,
                importance=0.2,
                is_risk_factor=has_suspicious_chars
            ),
            ScanFeatureCreate(
                feature_name='IP Address in URL',
                feature_value=1.0 if has_ip_address else 0.0,
                importance=0.3,
                is_risk_factor=has_ip_address
            ),
            ScanFeatureCreate(
                feature_name='Multiple Subdomains',
                feature_value=1.0 if has_multiple_subdomains else 0.0,
                importance=0.18,
                is_risk_factor=has_multiple_subdomains
            ),
            ScanFeatureCreate(
                feature_name='Non-standard Port',
                feature_value=1.0 if has_port else 0.0,
                importance=0.12,
                is_risk_factor=has_port
            ),
            ScanFeatureCreate(
                feature_name='Suspicious Keywords',
                feature_value=1.0 if has_suspicious_keywords else 0.0,
                importance=0.22,
                is_risk_factor=has_suspicious_keywords
            ),
            ScanFeatureCreate(
                feature_name='Number of Dashes',
                feature_value=number_of_dashes,
                importance=0.1,
                is_risk_factor=number_of_dashes > 3
            ),
        ]

        return features

    @staticmethod
    def calculate_risk_score(features: List[ScanFeatureCreate]) -> int:
        risk_score = 0
        total_importance = 0

        for feature in features:
            if feature.is_risk_factor:
                risk_score += feature.importance * 100
            total_importance += feature.importance

        return min(round((risk_score / total_importance) * 100), 100)

    @staticmethod
    def determine_classification(risk_score: int) -> Classification:
        if risk_score < 30:
            return Classification.BENIGN
        elif risk_score < 65:
            return Classification.DEFACEMENT
        else:
            return Classification.PHISHING

    @staticmethod
    def calculate_confidence(features: List[ScanFeatureCreate], classification: Classification) -> int:
        base_confidence = 85
        variance = random.random() * 10
        max_confidence = 98 if classification in [Classification.PHISHING, Classification.MALWARE] else 95
        return min(round(base_confidence + variance), max_confidence)

    @staticmethod
    def identify_risk_factors(url: str, features: List[ScanFeatureCreate]) -> List[RiskFactorCreate]:
        risk_factors = []

        for feature in features:
            if feature.is_risk_factor:
                severity = Severity.LOW
                description = ""

                if feature.feature_name == 'Has HTTPS':
                    severity = Severity.HIGH
                    description = 'URL does not use HTTPS encryption, making it vulnerable to man-in-the-middle attacks.'
                    risk_factors.append(RiskFactorCreate(
                        factor_name='No HTTPS Encryption',
                        severity=severity,
                        description=description
                    ))
                elif feature.feature_name == 'IP Address in URL':
                    severity = Severity.HIGH
                    description = 'URL uses an IP address instead of a domain name, which is commonly used in phishing attacks.'
                    risk_factors.append(RiskFactorCreate(
                        factor_name='IP-based URL',
                        severity=severity,
                        description=description
                    ))
                elif feature.feature_name == 'Suspicious Characters':
                    severity = Severity.MEDIUM
                    description = 'URL contains unusual or suspicious characters that may indicate an obfuscated malicious link.'
                    risk_factors.append(RiskFactorCreate(
                        factor_name='Unusual Characters',
                        severity=severity,
                        description=description
                    ))
                elif feature.feature_name == 'Multiple Subdomains':
                    severity = Severity.MEDIUM
                    description = 'Excessive subdomains detected, which can be used to impersonate legitimate websites.'
                    risk_factors.append(RiskFactorCreate(
                        factor_name='Complex Domain Structure',
                        severity=severity,
                        description=description
                    ))
                elif feature.feature_name == 'Suspicious Keywords':
                    severity = Severity.HIGH
                    description = 'URL contains keywords commonly associated with phishing attempts (login, verify, account).'
                    risk_factors.append(RiskFactorCreate(
                        factor_name='Phishing Keywords',
                        severity=severity,
                        description=description
                    ))
                elif feature.feature_name == 'URL Length':
                    severity = Severity.LOW
                    description = 'Unusually long URL detected, which may be used to hide malicious parameters.'
                    risk_factors.append(RiskFactorCreate(
                        factor_name='Excessive Length',
                        severity=severity,
                        description=description
                    ))

        return risk_factors

    @staticmethod
    def generate_recommendations(classification: Classification, risk_factors: List[RiskFactorCreate]) -> List[SecurityRecommendation]:
        recommendations = []

        if classification == Classification.BENIGN:
            recommendations.append(SecurityRecommendation(
                title='Safe to Proceed',
                description='This URL appears to be safe. However, always verify the destination before entering sensitive information.',
                priority=Severity.LOW
            ))
        else:
            if any(rf.factor_name == 'No HTTPS Encryption' for rf in risk_factors):
                recommendations.append(SecurityRecommendation(
                    title='Avoid Entering Sensitive Data',
                    description='Do not enter passwords, credit card information, or personal data on this site.',
                    priority=Severity.HIGH
                ))

            if any(rf.factor_name in ['IP-based URL', 'Phishing Keywords'] for rf in risk_factors):
                recommendations.append(SecurityRecommendation(
                    title='Possible Phishing Attempt',
                    description='Verify the legitimacy of this URL through official channels before proceeding.',
                    priority=Severity.HIGH
                ))

            recommendations.append(SecurityRecommendation(
                title='Use Antivirus Protection',
                description='Ensure your device has up-to-date antivirus software before visiting potentially risky sites.',
                priority=Severity.MEDIUM
            ))

            if classification in [Classification.PHISHING, Classification.MALWARE]:
                recommendations.append(SecurityRecommendation(
                    title='Do Not Visit',
                    description='This URL exhibits multiple high-risk characteristics. It is strongly recommended to avoid accessing it.',
                    priority=Severity.HIGH
                ))

        return recommendations

    @staticmethod
    def extract_ml_features(url: str, class_probabilities: dict) -> List[ScanFeatureCreate]:
        """Extract features based on ML model predictions"""
        url_length = len(url)
        has_suspicious_chars = bool(re.search(r'[<>{}[\]\\|^~`]', url))
        has_ip_address = bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))
        has_https = url.startswith('https://')
        
        # Get top features from ML model
        top_features = model_loader.get_feature_importance(url, 5)
        
        features = [
            ScanFeatureCreate(
                feature_name='URL Length',
                feature_value=float(url_length),
                importance=0.1,
                is_risk_factor=url_length > 75
            ),
            ScanFeatureCreate(
                feature_name='Has HTTPS',
                feature_value=1.0 if has_https else 0.0,
                importance=0.15,
                is_risk_factor=not has_https
            ),
            ScanFeatureCreate(
                feature_name='Suspicious Characters',
                feature_value=1.0 if has_suspicious_chars else 0.0,
                importance=0.12,
                is_risk_factor=has_suspicious_chars
            ),
            ScanFeatureCreate(
                feature_name='IP Address in URL',
                feature_value=1.0 if has_ip_address else 0.0,
                importance=0.2,
                is_risk_factor=has_ip_address
            ),
        ]
        
        # Add ML model probability features
        for class_name, probability in class_probabilities.items():
            features.append(ScanFeatureCreate(
                feature_name=f'{class_name.title()} Probability',
                feature_value=float(probability),
                importance=0.05,
                is_risk_factor=class_name in ['malware', 'phishing'] and probability > 0.3
            ))
        
        # Add top character n-gram features from ML model
        for i, (feature, value) in enumerate(top_features[:3]):
            features.append(ScanFeatureCreate(
                feature_name=f'Character Pattern: {feature}',
                feature_value=float(value),
                importance=0.08,
                is_risk_factor=value > 0.1
            ))
        
        return features

    @staticmethod
    def calculate_ml_risk_score(class_probabilities: dict, classification: Classification) -> int:
        """Calculate risk score based on ML class probabilities"""
        # Base risk score from malicious class probabilities
        malicious_prob = class_probabilities.get('malware', 0) + class_probabilities.get('phishing', 0)
        defacement_prob = class_probabilities.get('defacement', 0)
        
        # Calculate weighted risk score
        if classification == Classification.BENIGN:
            risk_score = malicious_prob * 100 + defacement_prob * 50
        elif classification == Classification.DEFACEMENT:
            risk_score = 40 + malicious_prob * 100
        elif classification == Classification.MALWARE:
            risk_score = 70 + defacement_prob * 30
        else:  # PHISHING
            risk_score = 80 + malicious_prob * 20
        
        return min(int(risk_score), 100)

    @staticmethod
    def identify_ml_risk_factors(url: str, classification: Classification, class_probabilities: dict) -> List[RiskFactorCreate]:
        """Identify risk factors based on ML classification"""
        risk_factors = []
        
        # High probability risk factors
        for class_name, probability in class_probabilities.items():
            if probability > 0.5 and class_name != 'benign':
                severity = Severity.HIGH if probability > 0.7 else Severity.MEDIUM
                description = f"ML model detects {probability*100:.1f}% probability of {class_name} activity"
                
                risk_factors.append(RiskFactorCreate(
                    factor_name=f'{class_name.title()} Detection',
                    severity=severity,
                    description=description
                ))
        
        # Classification-specific risk factors
        if classification == Classification.PHISHING:
            risk_factors.append(RiskFactorCreate(
                factor_name='Phishing Pattern Detected',
                severity=Severity.HIGH,
                description='URL exhibits characteristics commonly associated with phishing attempts'
            ))
        elif classification == Classification.MALWARE:
            risk_factors.append(RiskFactorCreate(
                factor_name='Malware Pattern Detected',
                severity=Severity.HIGH,
                description='URL shows patterns indicative of malware distribution'
            ))
        elif classification == Classification.DEFACEMENT:
            risk_factors.append(RiskFactorCreate(
                factor_name='Defacement Pattern Detected',
                severity=Severity.MEDIUM,
                description='URL may be associated with website defacement activities'
            ))
        
        # Traditional risk factors
        if not url.startswith('https://'):
            risk_factors.append(RiskFactorCreate(
                factor_name='No HTTPS Encryption',
                severity=Severity.HIGH,
                description='URL does not use HTTPS encryption'
            ))
        
        if re.search(r'\d+\.\d+\.\d+\.\d+', url):
            risk_factors.append(RiskFactorCreate(
                factor_name='IP-based URL',
                severity=Severity.HIGH,
                description='URL uses IP address instead of domain name'
            ))
        
        return risk_factors

    @staticmethod
    def generate_ml_recommendations(classification: Classification, risk_factors: List[RiskFactorCreate], class_probabilities: dict) -> List[SecurityRecommendation]:
        """Generate recommendations based on ML classification"""
        recommendations = []
        
        if classification == Classification.BENIGN:
            recommendations.append(SecurityRecommendation(
                title='Safe to Proceed',
                description='ML model indicates this URL is safe. Always verify before entering sensitive information.',
                priority=Severity.LOW
            ))
        else:
            # High-risk recommendations
            if classification in [Classification.PHISHING, Classification.MALWARE]:
                recommendations.append(SecurityRecommendation(
                    title='Do Not Visit',
                    description=f'ML model detects {class_probabilities.get(classification.value, 0)*100:.1f}% probability of {classification.value} activity.',
                    priority=Severity.HIGH
                ))
                
                recommendations.append(SecurityRecommendation(
                    title='Block URL',
                    description='Consider blocking this URL at network level.',
                    priority=Severity.HIGH
                ))
            
            # Medium-risk recommendations
            if classification == Classification.DEFACEMENT:
                recommendations.append(SecurityRecommendation(
                    title='Proceed with Caution',
                    description='URL may be associated with defacement activities. Verify legitimacy.',
                    priority=Severity.MEDIUM
                ))
            
            # General security recommendations
            recommendations.append(SecurityRecommendation(
                title='Use Security Software',
                description='Ensure antivirus and anti-malware protection is active.',
                priority=Severity.MEDIUM
            ))
            
            recommendations.append(SecurityRecommendation(
                title='Verify URL Legitimacy',
                description='Check URL through official security tools before accessing.',
                priority=Severity.MEDIUM
            ))
        
        return recommendations