"""
FastAPI application for Alert Processing System.
"""
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List
from uuid import UUID

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .config import settings
from .models import ProcessedAlert, RawAlert
from .workflows import alert_workflow
from .utils import security_validator

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class AlertRequest(BaseModel):
    """Request model for alert submission."""
    data: Dict[str, Any]
    source: str = "action_group"


class AlertResponse(BaseModel):
    """Response model for alert submission."""
    alert_id: UUID
    status: str
    message: str
    processing_started_at: datetime


class HealthResponse(BaseModel):
    """Health check response model."""
    status: str
    timestamp: datetime
    version: str
    environment: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("Starting Alert Processing System")
    
    # Startup tasks
    logger.info("Application startup complete")
    
    yield
    
    # Shutdown tasks
    logger.info("Shutting down Alert Processing System")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="AI Ops Alert Processing System with LangGraph and Presidio",
    lifespan=lifespan
)

# Add CORS middleware
if settings.environment == "development":
    # Permissive CORS for development
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://localhost:8080", "http://127.0.0.1:3000"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )
else:
    # Restrictive CORS for production
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "https://yourdomain.com",  # Replace with actual domain
            "https://*.yourdomain.com"  # Replace with actual domain
        ],
        allow_credentials=True,
        allow_methods=["GET", "POST"],  # Only necessary methods
        allow_headers=["Content-Type", "Authorization"],
    )


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.utcnow(),
        version=settings.app_version,
        environment=settings.environment
    )


@app.post("/api/v1/alerts", response_model=AlertResponse)
async def submit_alert(
    alert_request: AlertRequest, 
    background_tasks: BackgroundTasks
) -> AlertResponse:
    """
    Submit an alert for processing.
    
    Args:
        alert_request: Alert data and source
        background_tasks: FastAPI background tasks
        
    Returns:
        Alert response with ID and status
    """
    try:
        logger.info(f"Received alert from source: {alert_request.source}")
        
        # Security validation
        is_valid, security_issues = security_validator.validate_alert_data({
            "data": alert_request.data,
            "source": alert_request.source
        })
        
        if not is_valid:
            logger.warning(f"Security validation failed: {security_issues}")
            raise HTTPException(
                status_code=400, 
                detail=f"Security validation failed: {'; '.join(security_issues)}"
            )
        
        # Add processing task to background
        background_tasks.add_task(
            process_alert_background,
            alert_request.data,
            alert_request.source
        )
        
        # Generate a temporary response
        from uuid import uuid4
        alert_id = uuid4()
        
        return AlertResponse(
            alert_id=alert_id,
            status="accepted",
            message="Alert submitted for processing",
            processing_started_at=datetime.utcnow()
        )
        
    except HTTPException:
        raise  # Re-raise HTTP exceptions
    except Exception as e:
        logger.error(f"Failed to submit alert: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/v1/alerts/sync", response_model=ProcessedAlert)
async def submit_alert_sync(alert_request: AlertRequest) -> ProcessedAlert:
    """
    Submit an alert for synchronous processing.
    
    Args:
        alert_request: Alert data and source
        
    Returns:
        Processed alert
    """
    try:
        logger.info(f"Processing alert synchronously from source: {alert_request.source}")
        
        # Security validation
        is_valid, security_issues = security_validator.validate_alert_data({
            "data": alert_request.data,
            "source": alert_request.source
        })
        
        if not is_valid:
            logger.warning(f"Security validation failed: {security_issues}")
            raise HTTPException(
                status_code=400, 
                detail=f"Security validation failed: {'; '.join(security_issues)}"
            )
        
        # Process alert through workflow
        processed_alert = await alert_workflow.process_alert(
            alert_request.data, 
            alert_request.source
        )
        
        return processed_alert
        
    except HTTPException:
        raise  # Re-raise HTTP exceptions
    except Exception as e:
        logger.error(f"Failed to process alert synchronously: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/v1/alerts/{alert_id}", response_model=ProcessedAlert)
async def get_alert(alert_id: UUID) -> ProcessedAlert:
    """
    Get processed alert by ID.
    
    Args:
        alert_id: Alert identifier
        
    Returns:
        Processed alert
    """
    # In production, this would query the database
    logger.info(f"Retrieving alert: {alert_id}")
    raise HTTPException(status_code=404, detail="Alert not found")


@app.get("/api/v1/alerts", response_model=List[ProcessedAlert])
async def list_alerts(
    limit: int = 50, 
    offset: int = 0,
    status: str = None,
    category: str = None
) -> List[ProcessedAlert]:
    """
    List processed alerts with optional filtering.
    
    Args:
        limit: Maximum number of alerts to return
        offset: Number of alerts to skip
        status: Filter by alert status
        category: Filter by alert category
        
    Returns:
        List of processed alerts
    """
    # In production, this would query the database
    logger.info(f"Listing alerts: limit={limit}, offset={offset}")
    return []


@app.post("/api/v1/webhook/action-group")
async def action_group_webhook(
    data: Dict[str, Any],
    background_tasks: BackgroundTasks
) -> Dict[str, str]:
    """
    Webhook endpoint for Azure Action Groups.
    
    Args:
        data: Webhook payload from Action Group
        background_tasks: FastAPI background tasks
        
    Returns:
        Acknowledgment response
    """
    try:
        logger.info("Received webhook from Action Group")
        
        # Security validation
        is_valid, security_issues = security_validator.validate_alert_data({
            "data": data,
            "source": "action_group"
        })
        
        if not is_valid:
            logger.warning(f"Webhook security validation failed: {security_issues}")
            raise HTTPException(
                status_code=400, 
                detail=f"Security validation failed: {'; '.join(security_issues)}"
            )
        
        # Process alert in background
        background_tasks.add_task(
            process_alert_background,
            data,
            "action_group"
        )
        
        return {"status": "accepted", "message": "Alert received"}
        
    except HTTPException:
        raise  # Re-raise HTTP exceptions
    except Exception as e:
        logger.error(f"Webhook processing failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


async def process_alert_background(alert_data: Dict[str, Any], source: str):
    """Background task for alert processing."""
    try:
        logger.info(f"Background processing alert from {source}")
        
        processed_alert = await alert_workflow.process_alert(alert_data, source)
        
        # In production, save to database here
        logger.info(f"Alert {processed_alert.id} processed successfully in background")
        
    except Exception as e:
        logger.error(f"Background alert processing failed: {e}")


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "alert_processing.app:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )