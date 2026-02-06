"""
LangGraph workflow engine for alert processing.
"""
import logging
from datetime import datetime
from typing import Any, Dict

from langgraph.graph import StateGraph, END
from langchain.schema.runnable import RunnableConfig

from ..analyzers import alert_classifier, pii_detector
from ..collectors import collector
from ..enrichers import incident_correlator, log_enricher
from ..models import AlertStatus, ProcessedAlert, WorkflowState, AlertCategory

logger = logging.getLogger(__name__)


class AlertProcessingWorkflow:
    """LangGraph workflow for processing alerts through multiple stages."""
    
    def __init__(self):
        self.logger = logger
        self.graph = self._build_workflow()
        self.compiled_graph = self.graph.compile()
    
    def _build_workflow(self) -> StateGraph:
        """Build the LangGraph workflow."""
        
        # Create the state graph
        workflow = StateGraph(WorkflowState)
        
        # Add nodes
        workflow.add_node("collect", self._collect_node)
        workflow.add_node("validate", self._validate_node)
        workflow.add_node("detect_pii", self._pii_detection_node)
        workflow.add_node("anonymize", self._anonymize_node)
        workflow.add_node("classify", self._classify_node)
        workflow.add_node("enrich", self._enrich_node)
        workflow.add_node("correlate", self._correlate_node)
        workflow.add_node("finalize", self._finalize_node)
        workflow.add_node("error_handler", self._error_handler_node)
        
        # Set entry point
        workflow.set_entry_point("collect")
        
        # Add edges
        workflow.add_edge("collect", "validate")
        workflow.add_conditional_edges(
            "validate",
            self._should_continue_after_validation,
            {
                "continue": "detect_pii",
                "error": "error_handler",
                "duplicate": END
            }
        )
        
        workflow.add_conditional_edges(
            "detect_pii",
            self._should_anonymize,
            {
                "anonymize": "anonymize",
                "classify": "classify"
            }
        )
        
        workflow.add_edge("anonymize", "classify")
        workflow.add_edge("classify", "enrich")
        workflow.add_edge("enrich", "correlate")
        workflow.add_edge("correlate", "finalize")
        workflow.add_edge("finalize", END)
        workflow.add_edge("error_handler", END)
        
        return workflow
    
    async def process_alert(self, raw_alert_data: Dict[str, Any], source: str = "action_group") -> ProcessedAlert:
        """
        Process a raw alert through the complete workflow.
        
        Args:
            raw_alert_data: Raw alert data
            source: Alert source identifier
            
        Returns:
            Processed alert
        """
        try:
            start_time = datetime.utcnow()
            
            # Create initial workflow state
            initial_alert = await collector.collect_alert(raw_alert_data, source)
            
            initial_state = WorkflowState(
                alert=initial_alert,
                workflow_steps=[],
                current_step="collect",
                metadata={"start_time": start_time.isoformat()}
            )
            
            # Run the workflow
            config = RunnableConfig(configurable={"thread_id": str(initial_alert.id)})
            
            final_state = await self.compiled_graph.ainvoke(initial_state, config=config)
            
            # Calculate processing duration
            end_time = datetime.utcnow()
            processing_duration = (end_time - start_time).total_seconds()
            
            # Extract processed alert
            if isinstance(final_state.alert, ProcessedAlert):
                processed_alert = final_state.alert
                processed_alert.processing_duration = processing_duration
            else:
                # Convert if still RawAlert
                processed_alert = ProcessedAlert(
                    id=final_state.alert.id,
                    original_alert=final_state.alert,
                    status=AlertStatus.FAILED,
                    processing_duration=processing_duration,
                    error_message="Workflow did not complete processing"
                )
            
            self.logger.info(f"Alert {processed_alert.id} processed in {processing_duration:.2f}s")
            return processed_alert
            
        except Exception as e:
            self.logger.error(f"Alert processing failed: {e}")
            
            # Return failed alert
            return ProcessedAlert(
                id=initial_alert.id if 'initial_alert' in locals() else None,
                original_alert=initial_alert if 'initial_alert' in locals() else None,
                status=AlertStatus.FAILED,
                error_message=str(e),
                processing_duration=(datetime.utcnow() - start_time).total_seconds() if 'start_time' in locals() else None
            )
    
    # Workflow nodes
    
    async def _collect_node(self, state: WorkflowState) -> WorkflowState:
        """Collection node - already handled in process_alert."""
        self.logger.debug(f"Collect node: Alert {state.alert.id}")
        state.workflow_steps.append("collect")
        state.current_step = "validate"
        return state
    
    async def _validate_node(self, state: WorkflowState) -> WorkflowState:
        """Validation node."""
        try:
            self.logger.debug(f"Validate node: Alert {state.alert.id}")
            
            # Basic validation
            if not state.alert.title or not state.alert.description:
                raise ValueError("Alert missing required fields")
            
            # Check for duplicates (simplified)
            # In production, this would check against a database
            state.metadata["validation_passed"] = True
            
            state.workflow_steps.append("validate")
            state.current_step = "detect_pii"
            
            return state
            
        except Exception as e:
            self.logger.error(f"Validation failed for alert {state.alert.id}: {e}")
            state.error_count += 1
            state.metadata["validation_error"] = str(e)
            return state
    
    async def _pii_detection_node(self, state: WorkflowState) -> WorkflowState:
        """PII detection node."""
        try:
            self.logger.debug(f"PII detection node: Alert {state.alert.id}")
            
            # Detect PII in alert content
            combined_text = f"{state.alert.title} {state.alert.description}"
            has_pii, entities = await pii_detector.detect_pii(combined_text)
            
            state.metadata["has_pii"] = has_pii
            state.metadata["pii_entities"] = entities
            
            state.workflow_steps.append("detect_pii")
            
            if has_pii:
                state.current_step = "anonymize"
            else:
                state.current_step = "classify"
            
            return state
            
        except Exception as e:
            self.logger.error(f"PII detection failed for alert {state.alert.id}: {e}")
            state.error_count += 1
            state.metadata["pii_detection_error"] = str(e)
            state.current_step = "classify"  # Continue without PII handling
            return state
    
    async def _anonymize_node(self, state: WorkflowState) -> WorkflowState:
        """Anonymization node."""
        try:
            self.logger.debug(f"Anonymize node: Alert {state.alert.id}")
            
            entities = state.metadata.get("pii_entities", [])
            
            # Anonymize title and description
            anonymized_title = await pii_detector.anonymize_text(state.alert.title, entities)
            anonymized_description = await pii_detector.anonymize_text(state.alert.description, entities)
            
            state.metadata["anonymized_content"] = {
                "title": anonymized_title,
                "description": anonymized_description
            }
            
            state.workflow_steps.append("anonymize")
            state.current_step = "classify"
            
            return state
            
        except Exception as e:
            self.logger.error(f"Anonymization failed for alert {state.alert.id}: {e}")
            state.error_count += 1
            state.metadata["anonymization_error"] = str(e)
            state.current_step = "classify"
            return state
    
    async def _classify_node(self, state: WorkflowState) -> WorkflowState:
        """Classification node."""
        try:
            self.logger.debug(f"Classify node: Alert {state.alert.id}")
            
            # Classify alert
            category, urgency = await alert_classifier.classify_alert(state.alert)
            
            # Analyze sentiment
            combined_text = f"{state.alert.title} {state.alert.description}"
            sentiment = await alert_classifier.analyze_sentiment(combined_text)
            
            # Create ProcessedAlert if not already created
            if not isinstance(state.alert, ProcessedAlert):
                processed_alert = ProcessedAlert(
                    id=state.alert.id,
                    original_alert=state.alert,
                    status=AlertStatus.ANALYZED
                )
                state.alert = processed_alert
            
            # Update classification results
            state.alert.category = category
            state.alert.urgency_score = urgency
            state.alert.sentiment_score = sentiment
            
            # Handle PII information
            if state.metadata.get("has_pii"):
                state.alert.contains_pii = True
                state.alert.anonymized_content = state.metadata.get("anonymized_content")
            
            state.workflow_steps.append("classify")
            state.current_step = "enrich"
            
            return state
            
        except Exception as e:
            self.logger.error(f"Classification failed for alert {state.alert.id}: {e}")
            state.error_count += 1
            state.metadata["classification_error"] = str(e)
            state.current_step = "enrich"
            return state
    
    async def _enrich_node(self, state: WorkflowState) -> WorkflowState:
        """Enrichment node."""
        try:
            self.logger.debug(f"Enrich node: Alert {state.alert.id}")
            
            # Enrich with log analytics data
            enrichment_data = await log_enricher.enrich_alert(state.alert.original_alert)
            
            if isinstance(state.alert, ProcessedAlert):
                state.alert.enrichment_data = enrichment_data
                state.alert.status = AlertStatus.ENRICHED
            
            state.workflow_steps.append("enrich")
            state.current_step = "correlate"
            
            return state
            
        except Exception as e:
            self.logger.error(f"Enrichment failed for alert {state.alert.id}: {e}")
            state.error_count += 1
            state.metadata["enrichment_error"] = str(e)
            state.current_step = "correlate"
            return state
    
    async def _correlate_node(self, state: WorkflowState) -> WorkflowState:
        """Incident correlation node."""
        try:
            self.logger.debug(f"Correlate node: Alert {state.alert.id}")
            
            # Find related incidents
            related_incidents = await incident_correlator.find_related_incidents(state.alert.original_alert)
            
            if isinstance(state.alert, ProcessedAlert):
                state.alert.related_incidents = related_incidents
            
            state.workflow_steps.append("correlate")
            state.current_step = "finalize"
            
            return state
            
        except Exception as e:
            self.logger.error(f"Correlation failed for alert {state.alert.id}: {e}")
            state.error_count += 1
            state.metadata["correlation_error"] = str(e)
            state.current_step = "finalize"
            return state
    
    async def _finalize_node(self, state: WorkflowState) -> WorkflowState:
        """Finalization node."""
        try:
            self.logger.debug(f"Finalize node: Alert {state.alert.id}")
            
            if isinstance(state.alert, ProcessedAlert):
                state.alert.status = AlertStatus.COMPLETED
                state.alert.processed_at = datetime.utcnow()
            
            state.workflow_steps.append("finalize")
            state.current_step = "completed"
            
            return state
            
        except Exception as e:
            self.logger.error(f"Finalization failed for alert {state.alert.id}: {e}")
            state.error_count += 1
            return state
    
    async def _error_handler_node(self, state: WorkflowState) -> WorkflowState:
        """Error handling node."""
        self.logger.error(f"Error handler: Alert {state.alert.id} had {state.error_count} errors")
        
        if isinstance(state.alert, ProcessedAlert):
            state.alert.status = AlertStatus.FAILED
        
        state.workflow_steps.append("error_handler")
        return state
    
    # Conditional edge functions
    
    def _should_continue_after_validation(self, state: WorkflowState) -> str:
        """Determine next step after validation."""
        if state.metadata.get("validation_error"):
            return "error"
        elif state.metadata.get("is_duplicate"):
            return "duplicate"
        else:
            return "continue"
    
    def _should_anonymize(self, state: WorkflowState) -> str:
        """Determine if anonymization is needed."""
        if state.metadata.get("has_pii", False):
            return "anonymize"
        else:
            return "classify"


# Global workflow instance
alert_workflow = AlertProcessingWorkflow()