"""
Alert analysis components including PII detection and classification.
"""
import logging
from typing import Any, Dict, List, Optional, Tuple

from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

from ..config import settings
from ..models import AlertCategory, ProcessedAlert, RawAlert

logger = logging.getLogger(__name__)


class PIIDetector:
    """Detects PII in alert content using Presidio."""
    
    def __init__(self):
        self.logger = logger
        self.analyzer = None
        self.anonymizer = None
        self._initialize_engines()
    
    def _initialize_engines(self):
        """Initialize Presidio analyzer and anonymizer engines."""
        try:
            # Initialize analyzer engine
            self.analyzer = AnalyzerEngine()
            
            # Initialize anonymizer engine
            self.anonymizer = AnonymizerEngine()
            
            self.logger.info("Presidio engines initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Presidio engines: {e}")
            # Fall back to mock implementation for development
            self.analyzer = None
            self.anonymizer = None
    
    async def detect_pii(self, text: str, language: str = "en") -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Detect PII in text content.
        
        Args:
            text: Text to analyze
            language: Language code (default: en)
            
        Returns:
            Tuple of (has_pii, entities_found)
        """
        if not self.analyzer:
            # Mock implementation for development
            self.logger.warning("Presidio analyzer not available, using mock PII detection")
            return False, []
        
        try:
            # Analyze text for PII
            results = self.analyzer.analyze(
                text=text, 
                language=language,
                entities=None  # Detect all entity types
            )
            
            # Convert results to dict format
            entities = []
            for result in results:
                entities.append({
                    "entity_type": result.entity_type,
                    "start": result.start,
                    "end": result.end,
                    "confidence": result.score,
                    "text": text[result.start:result.end]
                })
            
            has_pii = len(entities) > 0
            
            if has_pii:
                self.logger.info(f"PII detected: {len(entities)} entities found")
            
            return has_pii, entities
            
        except Exception as e:
            self.logger.error(f"PII detection failed: {e}")
            # Return safe default
            return False, []
    
    async def anonymize_text(self, text: str, entities: List[Dict[str, Any]]) -> str:
        """
        Anonymize detected PII in text.
        
        Args:
            text: Original text
            entities: PII entities to anonymize
            
        Returns:
            Anonymized text
        """
        if not self.anonymizer or not entities:
            return text
        
        try:
            # Convert our entities back to Presidio format
            from presidio_analyzer import RecognizerResult
            
            recognizer_results = []
            for entity in entities:
                result = RecognizerResult(
                    entity_type=entity["entity_type"],
                    start=entity["start"],
                    end=entity["end"],
                    score=entity["confidence"]
                )
                recognizer_results.append(result)
            
            # Anonymize based on configuration
            if settings.anonymize_with_fake_data:
                # Use fake data replacement
                anonymized_result = self.anonymizer.anonymize(
                    text=text,
                    analyzer_results=recognizer_results,
                    operators={"DEFAULT": {"type": "replace"}}
                )
            else:
                # Use token replacement (more secure)
                anonymized_result = self.anonymizer.anonymize(
                    text=text,
                    analyzer_results=recognizer_results,
                    operators={"DEFAULT": {"type": "mask", "masking_char": "*", "chars_to_mask": 4, "from_end": True}}
                )
            
            return anonymized_result.text
            
        except Exception as e:
            self.logger.error(f"Text anonymization failed: {e}")
            # Return original text if anonymization fails
            return text


class AlertClassifier:
    """Classifies alerts into categories and calculates urgency scores."""
    
    def __init__(self):
        self.logger = logger
        
        # Category keywords for rule-based classification
        self.category_keywords = {
            AlertCategory.INFRASTRUCTURE: [
                "server", "vm", "virtual machine", "instance", "hardware", "cpu", "memory", 
                "disk", "storage", "network", "connectivity", "infrastructure"
            ],
            AlertCategory.APPLICATION: [
                "application", "app", "service", "api", "endpoint", "response time", 
                "latency", "error rate", "exception", "crash", "deployment"
            ],
            AlertCategory.SECURITY: [
                "security", "breach", "attack", "vulnerability", "malware", "unauthorized", 
                "suspicious", "intrusion", "firewall", "authentication", "access denied"
            ],
            AlertCategory.PERFORMANCE: [
                "performance", "slow", "timeout", "latency", "response time", "throughput", 
                "bottleneck", "optimization", "load", "capacity"
            ],
            AlertCategory.NETWORK: [
                "network", "connectivity", "dns", "routing", "bandwidth", "packet loss", 
                "firewall", "load balancer", "proxy", "vpn"
            ],
            AlertCategory.DATABASE: [
                "database", "db", "sql", "query", "connection pool", "deadlock", "backup", 
                "replication", "index", "table"
            ]
        }
        
        # Severity to urgency mapping
        self.severity_urgency_map = {
            "critical": 0.9,
            "high": 0.7,
            "medium": 0.5,
            "low": 0.3,
            "info": 0.1
        }
    
    async def classify_alert(self, alert: RawAlert) -> Tuple[AlertCategory, float]:
        """
        Classify alert and calculate urgency score.
        
        Args:
            alert: Raw alert to classify
            
        Returns:
            Tuple of (category, urgency_score)
        """
        try:
            # Combine title and description for analysis
            text_content = f"{alert.title} {alert.description}".lower()
            
            # Rule-based classification
            category_scores = {}
            
            for category, keywords in self.category_keywords.items():
                score = 0
                for keyword in keywords:
                    if keyword in text_content:
                        score += 1
                
                if score > 0:
                    category_scores[category] = score / len(keywords)
            
            # Determine best category
            if category_scores:
                best_category = max(category_scores.items(), key=lambda x: x[1])[0]
                confidence = max(category_scores.values())
            else:
                best_category = AlertCategory.UNKNOWN
                confidence = 0.0
            
            # Calculate urgency score
            base_urgency = self.severity_urgency_map.get(alert.severity.value, 0.5)
            
            # Adjust based on category
            category_multipliers = {
                AlertCategory.SECURITY: 1.2,
                AlertCategory.INFRASTRUCTURE: 1.1,
                AlertCategory.APPLICATION: 1.0,
                AlertCategory.PERFORMANCE: 0.9,
                AlertCategory.NETWORK: 0.95,
                AlertCategory.DATABASE: 1.05,
                AlertCategory.UNKNOWN: 0.8
            }
            
            urgency_score = min(1.0, base_urgency * category_multipliers.get(best_category, 1.0))
            
            self.logger.info(f"Alert {alert.id} classified as {best_category.value} with urgency {urgency_score:.2f}")
            
            return best_category, urgency_score
            
        except Exception as e:
            self.logger.error(f"Alert classification failed: {e}")
            return AlertCategory.UNKNOWN, 0.5
    
    async def analyze_sentiment(self, text: str) -> float:
        """
        Basic sentiment analysis of alert text.
        
        Args:
            text: Text to analyze
            
        Returns:
            Sentiment score between -1 (negative) and 1 (positive)
        """
        # Simple rule-based sentiment analysis
        # In production, you'd use a proper sentiment analysis model
        
        negative_words = [
            "error", "fail", "failure", "critical", "urgent", "down", "outage", 
            "breach", "attack", "slow", "timeout", "crash", "dead", "broken"
        ]
        
        positive_words = [
            "resolved", "fixed", "recovered", "stable", "normal", "healthy", 
            "success", "complete", "optimal"
        ]
        
        text_lower = text.lower()
        
        negative_count = sum(1 for word in negative_words if word in text_lower)
        positive_count = sum(1 for word in positive_words if word in text_lower)
        
        total_words = len(text.split())
        
        if total_words == 0:
            return 0.0
        
        # Calculate sentiment score
        sentiment = (positive_count - negative_count) / max(total_words, 1)
        
        # Normalize to [-1, 1] range
        return max(-1.0, min(1.0, sentiment * 10))


# Global instances
pii_detector = PIIDetector()
alert_classifier = AlertClassifier()