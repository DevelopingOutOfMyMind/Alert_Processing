"""
Alert enrichment components for Log Analytics integration.
"""
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

try:
    from azure.identity import DefaultAzureCredential
    from azure.monitor.query import LogsQueryClient
    from azure.core.exceptions import AzureError
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False
    DefaultAzureCredential = None
    LogsQueryClient = None
    AzureError = Exception

from ..config import settings
from ..models import EnrichmentQuery, EnrichmentResult, ProcessedAlert, RawAlert
from ..utils.security import security_validator

logger = logging.getLogger(__name__)


class LogAnalyticsEnricher:
    """Enriches alerts with data from Azure Log Analytics."""
    
    def __init__(self):
        self.logger = logger
        self.client = None
        self.workspace_id = settings.azure_log_analytics_workspace_id
        
        if AZURE_AVAILABLE and self.workspace_id:
            self._initialize_client()
        else:
            self.logger.warning("Azure Log Analytics not available - using mock enrichment")
    
    def _initialize_client(self):
        """Initialize Azure Log Analytics client."""
        try:
            credential = DefaultAzureCredential()
            self.client = LogsQueryClient(credential)
            self.logger.info("Log Analytics client initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Log Analytics client: {e}")
            self.client = None
    
    async def enrich_alert(self, alert: RawAlert) -> Dict[str, Any]:
        """
        Enrich alert with related log data.
        
        Args:
            alert: Raw alert to enrich
            
        Returns:
            Dictionary of enrichment data
        """
        enrichment_data = {}
        
        try:
            # Generate queries based on alert content
            queries = self._generate_enrichment_queries(alert)
            
            for query_name, query_info in queries.items():
                try:
                    result = await self._execute_query(query_info)
                    enrichment_data[query_name] = {
                        "result_count": result.result_count,
                        "results": result.results,
                        "execution_time": result.execution_time
                    }
                    
                except Exception as e:
                    self.logger.error(f"Enrichment query '{query_name}' failed: {e}")
                    enrichment_data[query_name] = {"error": str(e)}
            
            # Calculate overall impact score
            impact_score = self._calculate_impact_score(enrichment_data)
            enrichment_data["impact_score"] = impact_score
            
            self.logger.info(f"Alert {alert.id} enriched with {len(enrichment_data)} datasets")
            
            return enrichment_data
            
        except Exception as e:
            self.logger.error(f"Alert enrichment failed: {e}")
            return {"error": str(e)}
    
    def _generate_enrichment_queries(self, alert: RawAlert) -> Dict[str, EnrichmentQuery]:
        """Generate KQL queries for alert enrichment."""
        queries = {}
        
        # Extract key information from alert
        resource_name = alert.metadata.get("resource_name")
        resource_group = alert.metadata.get("resource_group")
        
        # Time range for queries (last 24 hours from alert time)
        alert_time = alert.timestamp
        start_time = alert_time - timedelta(hours=24)
        
        # Query 1: Related errors from the same resource
        if resource_name:
            # Sanitize resource name to prevent injection
            safe_resource_name = security_validator.sanitize_kql_string(resource_name)
            queries["related_errors"] = EnrichmentQuery(
                alert_id=alert.id,
                query_text=f"""
                AzureDiagnostics
                | where TimeGenerated between (datetime('{start_time.isoformat()}') .. datetime('{alert_time.isoformat()}'))
                | where Resource == '{safe_resource_name}'
                | where Level in ("Error", "Critical")
                | summarize count() by bin(TimeGenerated, 1h), Level
                | order by TimeGenerated desc
                """,
                timerange_hours=24
            )
        
        # Query 2: Performance metrics
        if resource_name:
            safe_resource_name = security_validator.sanitize_kql_string(resource_name)
            queries["performance_metrics"] = EnrichmentQuery(
                alert_id=alert.id,
                query_text=f"""
                Perf
                | where TimeGenerated between (datetime('{start_time.isoformat()}') .. datetime('{alert_time.isoformat()}'))
                | where Computer == '{safe_resource_name}'
                | where CounterName in ("% Processor Time", "Available MBytes", "Disk Reads/sec", "Disk Writes/sec")
                | summarize avg(CounterValue) by bin(TimeGenerated, 15m), CounterName
                | order by TimeGenerated desc
                """,
                timerange_hours=24
            )
        
        # Query 3: Security events
        queries["security_events"] = EnrichmentQuery(
            alert_id=alert.id,
            query_text=f"""
            SecurityEvent
            | where TimeGenerated between (datetime('{start_time.isoformat()}') .. datetime('{alert_time.isoformat()}'))
            | where EventLevelName in ("Warning", "Error")
            | summarize count() by bin(TimeGenerated, 1h), Activity
            | order by count_ desc
            | take 50
            """,
            timerange_hours=24
        )
        
        # Query 4: Custom logs related to the alert
        if alert.title or alert.description:
            # Extract keywords for search
            keywords = self._extract_keywords(f"{alert.title} {alert.description}")
            if keywords:
                # Sanitize keywords to prevent injection
                safe_keywords = [security_validator.sanitize_kql_string(keyword) for keyword in keywords[:5]]
                keyword_filter = " or ".join([f'* contains "{keyword}"' for keyword in safe_keywords])
                queries["custom_logs"] = EnrichmentQuery(
                    alert_id=alert.id,
                    query_text=f"""
                    search in (AppServiceHTTPLogs, AppServiceConsoleLogs, AppServiceAppLogs) 
                    TimeGenerated between (datetime('{start_time.isoformat()}') .. datetime('{alert_time.isoformat()}'))
                    and ({keyword_filter})
                    | take 100
                    """,
                    timerange_hours=24
                )
        
        return queries
    
    def _extract_keywords(self, text: str) -> List[str]:
        """Extract meaningful keywords from text."""
        # Simple keyword extraction
        stop_words = {
            "the", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", 
            "by", "is", "are", "was", "were", "be", "been", "being", "have", "has", 
            "had", "do", "does", "did", "will", "would", "could", "should", "may", 
            "might", "must", "can", "a", "an", "this", "that", "these", "those"
        }
        
        words = text.lower().split()
        keywords = [word.strip(".,!?;:()[]{}") for word in words 
                   if len(word) > 3 and word.lower() not in stop_words]
        
        return list(set(keywords))[:10]  # Return unique keywords, max 10
    
    async def _execute_query(self, query: EnrichmentQuery) -> EnrichmentResult:
        """Execute a KQL query against Log Analytics."""
        if not self.client:
            # Mock implementation for development
            return EnrichmentResult(
                alert_id=query.alert_id,
                query_executed=query.query_text,
                results=[],
                result_count=0,
                execution_time=0.1
            )
        
        try:
            start_time = datetime.utcnow()
            
            response = self.client.query_workspace(
                workspace_id=self.workspace_id,
                query=query.query_text,
                timespan=timedelta(hours=query.timerange_hours)
            )
            
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Convert results to list of dictionaries
            results = []
            if response.tables:
                table = response.tables[0]
                columns = [col.name for col in table.columns]
                
                for row in table.rows:
                    result_dict = dict(zip(columns, row))
                    results.append(result_dict)
            
            return EnrichmentResult(
                alert_id=query.alert_id,
                query_executed=query.query_text,
                results=results[:query.max_results],
                result_count=len(results),
                execution_time=execution_time
            )
            
        except AzureError as e:
            self.logger.error(f"Azure Log Analytics query failed: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Query execution failed: {e}")
            raise
    
    def _calculate_impact_score(self, enrichment_data: Dict[str, Any]) -> float:
        """Calculate overall impact score based on enrichment data."""
        try:
            impact_factors = []
            
            # Factor 1: Number of related errors
            if "related_errors" in enrichment_data and "results" in enrichment_data["related_errors"]:
                error_count = len(enrichment_data["related_errors"]["results"])
                error_impact = min(1.0, error_count / 50)  # Normalize to 0-1
                impact_factors.append(error_impact)
            
            # Factor 2: Performance degradation
            if "performance_metrics" in enrichment_data and "results" in enrichment_data["performance_metrics"]:
                # Simplified: assume any performance data indicates some impact
                perf_impact = 0.5
                impact_factors.append(perf_impact)
            
            # Factor 3: Security events
            if "security_events" in enrichment_data and "results" in enrichment_data["security_events"]:
                security_count = len(enrichment_data["security_events"]["results"])
                security_impact = min(1.0, security_count / 10)
                impact_factors.append(security_impact * 1.2)  # Weight security higher
            
            # Calculate weighted average
            if impact_factors:
                return sum(impact_factors) / len(impact_factors)
            else:
                return 0.0
                
        except Exception as e:
            self.logger.error(f"Impact score calculation failed: {e}")
            return 0.0


class IncidentCorrelator:
    """Correlates alerts with existing incidents."""
    
    def __init__(self):
        self.logger = logger
        self.correlation_threshold = 0.7
    
    async def find_related_incidents(self, alert: RawAlert) -> List[str]:
        """
        Find related incidents for an alert.
        
        Args:
            alert: Alert to correlate
            
        Returns:
            List of related incident IDs
        """
        try:
            # Mock implementation - in production this would query a database
            # of existing incidents and use similarity algorithms
            
            related_incidents = []
            
            # Simple correlation based on resource name and alert type
            if alert.metadata.get("resource_name"):
                # Simulate finding related incidents
                related_incidents.append(f"INC-{hash(alert.metadata['resource_name']) % 10000:04d}")
            
            self.logger.info(f"Found {len(related_incidents)} related incidents for alert {alert.id}")
            
            return related_incidents
            
        except Exception as e:
            self.logger.error(f"Incident correlation failed: {e}")
            return []


# Global instances
log_enricher = LogAnalyticsEnricher()
incident_correlator = IncidentCorrelator()