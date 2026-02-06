"""
Alert collection components.
"""
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import ValidationError

from ..config import settings
from ..models import AlertSeverity, RawAlert

logger = logging.getLogger(__name__)


class AlertCollector:
    """Collects and parses incoming alerts from various sources."""
    
    def __init__(self):
        self.logger = logger
        self.supported_sources = {
            "azure_monitor",
            "prometheus",
            "grafana",
            "custom",
            "action_group"
        }
    
    async def collect_alert(self, raw_data: Dict[str, Any], source: str = "action_group") -> RawAlert:
        """
        Collect and parse a raw alert from source data.
        
        Args:
            raw_data: Raw alert data from source
            source: Alert source identifier
            
        Returns:
            Parsed RawAlert object
            
        Raises:
            ValueError: If alert data is invalid
        """
        try:
            # Validate source
            if source not in self.supported_sources:
                self.logger.warning(f"Unknown alert source: {source}")
                source = "custom"
            
            # Parse based on source type
            if source == "action_group":
                alert = await self._parse_action_group_alert(raw_data)
            elif source == "azure_monitor":
                alert = await self._parse_azure_monitor_alert(raw_data)
            else:
                alert = await self._parse_generic_alert(raw_data, source)
            
            self.logger.info(f"Successfully collected alert {alert.id} from {source}")
            return alert
            
        except ValidationError as e:
            self.logger.error(f"Alert validation failed: {e}")
            raise ValueError(f"Invalid alert data: {e}")
        except Exception as e:
            self.logger.error(f"Failed to collect alert from {source}: {e}")
            raise
    
    async def _parse_action_group_alert(self, raw_data: Dict[str, Any]) -> RawAlert:
        """Parse alert from Azure Action Group."""
        try:
            # Extract standard fields from Action Group format
            alert_data = raw_data.get("data", {})
            alert_context = alert_data.get("context", {})
            
            title = alert_context.get("name") or alert_data.get("alertname", "Unknown Alert")
            description = alert_context.get("description") or alert_data.get("description", "")
            
            # Map severity
            severity_mapping = {
                "critical": AlertSeverity.CRITICAL,
                "high": AlertSeverity.HIGH,
                "medium": AlertSeverity.MEDIUM,
                "low": AlertSeverity.LOW,
                "info": AlertSeverity.INFO,
                "informational": AlertSeverity.INFO,
                "warning": AlertSeverity.MEDIUM,
                "error": AlertSeverity.HIGH,
            }
            
            raw_severity = alert_context.get("severity", "medium").lower()
            severity = severity_mapping.get(raw_severity, AlertSeverity.MEDIUM)
            
            # Extract timestamp
            timestamp_str = alert_context.get("timestamp") or raw_data.get("timestamp")
            if timestamp_str:
                if isinstance(timestamp_str, str):
                    timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                else:
                    timestamp = datetime.utcnow()
            else:
                timestamp = datetime.utcnow()
            
            # Build metadata
            metadata = {
                "resource_group": alert_context.get("resourceGroupName"),
                "resource_name": alert_context.get("resourceName"),
                "resource_type": alert_context.get("resourceType"),
                "subscription_id": alert_context.get("subscriptionId"),
                "condition_type": alert_context.get("conditionType"),
                "monitor_condition": alert_context.get("monitorCondition"),
            }
            
            # Remove None values
            metadata = {k: v for k, v in metadata.items() if v is not None}
            
            return RawAlert(
                timestamp=timestamp,
                source="action_group",
                title=title,
                description=description,
                severity=severity,
                metadata=metadata,
                raw_data=raw_data
            )
            
        except Exception as e:
            self.logger.error(f"Failed to parse Action Group alert: {e}")
            raise ValueError(f"Invalid Action Group alert format: {e}")
    
    async def _parse_azure_monitor_alert(self, raw_data: Dict[str, Any]) -> RawAlert:
        """Parse Azure Monitor alert format."""
        try:
            # Azure Monitor has different format
            alert_rule = raw_data.get("data", {}).get("alertRule", {})
            
            title = alert_rule.get("name", "Azure Monitor Alert")
            description = alert_rule.get("description", "")
            
            # Map condition to severity
            condition = raw_data.get("data", {}).get("status", "").lower()
            severity = AlertSeverity.MEDIUM
            if "critical" in condition or "fired" in condition:
                severity = AlertSeverity.HIGH
            
            return RawAlert(
                source="azure_monitor",
                title=title,
                description=description,
                severity=severity,
                metadata={"alert_rule": alert_rule},
                raw_data=raw_data
            )
            
        except Exception as e:
            self.logger.error(f"Failed to parse Azure Monitor alert: {e}")
            raise ValueError(f"Invalid Azure Monitor alert format: {e}")
    
    async def _parse_generic_alert(self, raw_data: Dict[str, Any], source: str) -> RawAlert:
        """Parse generic alert format."""
        try:
            # Try to extract common fields
            title = (
                raw_data.get("title") or 
                raw_data.get("summary") or 
                raw_data.get("alertname") or 
                "Generic Alert"
            )
            
            description = (
                raw_data.get("description") or 
                raw_data.get("message") or 
                raw_data.get("details") or 
                ""
            )
            
            # Default to medium severity for unknown formats
            severity = AlertSeverity.MEDIUM
            if raw_data.get("severity"):
                severity_str = str(raw_data["severity"]).lower()
                if severity_str in ["critical", "crit", "fatal"]:
                    severity = AlertSeverity.CRITICAL
                elif severity_str in ["high", "error", "err"]:
                    severity = AlertSeverity.HIGH
                elif severity_str in ["low", "debug"]:
                    severity = AlertSeverity.LOW
                elif severity_str in ["info", "informational"]:
                    severity = AlertSeverity.INFO
            
            return RawAlert(
                source=source,
                title=title,
                description=description,
                severity=severity,
                metadata={"original_format": "generic"},
                raw_data=raw_data
            )
            
        except Exception as e:
            self.logger.error(f"Failed to parse generic alert: {e}")
            raise ValueError(f"Invalid generic alert format: {e}")
    
    async def batch_collect_alerts(self, alerts_data: List[Dict[str, Any]], source: str = "action_group") -> List[RawAlert]:
        """Collect multiple alerts in batch."""
        collected_alerts = []
        failed_count = 0
        
        for alert_data in alerts_data:
            try:
                alert = await self.collect_alert(alert_data, source)
                collected_alerts.append(alert)
            except Exception as e:
                self.logger.error(f"Failed to collect alert from batch: {e}")
                failed_count += 1
        
        self.logger.info(f"Batch collection complete: {len(collected_alerts)} success, {failed_count} failed")
        return collected_alerts


# Global collector instance
collector = AlertCollector()