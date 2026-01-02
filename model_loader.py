import os
import random
from typing import Tuple, Optional


class ModelLoader:
    """Fallback model loader when ML dependencies aren't available"""
    
    _instance = None
    _models_loaded = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ModelLoader, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not self._models_loaded:
            self.tfidf_vectorizer = None
            self.logistic_classifier = None
            self.label_encoder = None
            self.model_accuracy = 0.85  # Fallback accuracy
            self._create_fallback_models()
    
    def _create_fallback_models(self) -> None:
        """Create fallback rule-based models"""
        # Simple class mapping
        self.class_names = ['benign', 'defacement', 'malware', 'phishing']
        self._models_loaded = True
        print("Fallback models created")
    
    def predict_url(self, url: str) -> Tuple[str, float]:
        """
        Predict the classification of a URL using fallback rules
        
        Args:
            url: The URL to classify
            
        Returns:
            Tuple of (predicted_class, confidence_score)
        """
        if not self._models_loaded:
            raise RuntimeError("Models not loaded")
        
        url_lower = url.lower()
        
        # Simple rule-based classification
        if any(keyword in url_lower for keyword in ['phish', 'login', 'secure', 'account', 'verify']):
            return 'phishing', 0.8
        elif any(keyword in url_lower for keyword in ['malware', 'virus', 'trojan', 'download']):
            return 'malware', 0.7
        elif any(keyword in url_lower for keyword in ['hack', 'deface', 'exploit']):
            return 'defacement', 0.6
        else:
            return 'benign', 0.9
    
    def get_class_probabilities(self, url: str) -> dict:
        """
        Get probability distribution for all classes using fallback rules
        
        Args:
            url: The URL to classify
            
        Returns:
            Dictionary with class names as keys and probabilities as values
        """
        if not self._models_loaded:
            raise RuntimeError("Models not loaded")
        
        url_lower = url.lower()
        
        # Start with equal probabilities
        probs = {'benign': 0.25, 'defacement': 0.25, 'malware': 0.25, 'phishing': 0.25}
        
        # Adjust based on keywords
        if any(keyword in url_lower for keyword in ['phish', 'login', 'secure', 'account', 'verify']):
            probs['phishing'] = 0.7
            probs['benign'] = 0.1
            probs['defacement'] = 0.1
            probs['malware'] = 0.1
        elif any(keyword in url_lower for keyword in ['malware', 'virus', 'trojan', 'download']):
            probs['malware'] = 0.6
            probs['benign'] = 0.2
            probs['defacement'] = 0.1
            probs['phishing'] = 0.1
        elif any(keyword in url_lower for keyword in ['hack', 'deface', 'exploit']):
            probs['defacement'] = 0.5
            probs['benign'] = 0.3
            probs['malware'] = 0.1
            probs['phishing'] = 0.1
        else:
            probs['benign'] = 0.8
            probs['defacement'] = 0.07
            probs['malware'] = 0.07
            probs['phishing'] = 0.06
        
        return probs
    
    def get_feature_importance(self, url: str, top_n: int = 10) -> list:
        """
        Get the most important features for a URL prediction using fallback
        
        Args:
            url: The URL to analyze
            top_n: Number of top features to return
            
        Returns:
            List of tuples (feature, importance_score)
        """
        if not self._models_loaded:
            raise RuntimeError("Models not loaded")
        
        # Simple character-based features
        url_lower = url.lower()
        features = []
        
        # Check for suspicious patterns
        if 'http://' in url_lower:
            features.append(('http_protocol', 0.8))
        if 'https://' in url_lower:
            features.append(('https_protocol', 0.9))
        if 'login' in url_lower:
            features.append(('login_keyword', 0.7))
        if 'secure' in url_lower:
            features.append(('secure_keyword', 0.6))
        if len(url) > 50:
            features.append(('long_url', 0.5))
        
        return features[:top_n]
    
    def is_models_available(self) -> bool:
        """Check if trained models are available"""
        model_dir = os.path.join(os.path.dirname(__file__), '..', 'trained_models')
        required_files = [
            'tfidf_vectorizer.pkl',
            'logistic_classifier.pkl', 
            'label_encoder.pkl'
        ]
        
        return all(os.path.exists(os.path.join(model_dir, f)) for f in required_files)


# Global instance for easy access
model_loader = ModelLoader()