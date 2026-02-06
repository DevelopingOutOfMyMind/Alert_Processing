"""
Command Line Interface for Alert Processing System.
"""
import json
import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from .config import settings
from .workflows import alert_workflow

app = typer.Typer(
    name="alert-processor",
    help="AI Ops Alert Processing System CLI",
    add_completion=False
)

console = Console()


@app.command()
def process_file(
    file_path: Path = typer.Argument(..., help="Path to JSON file containing alert data"),
    source: str = typer.Option("action_group", help="Alert source type"),
    output: Optional[Path] = typer.Option(None, help="Output file for processed alert")
):
    """Process an alert from a JSON file."""
    try:
        # Read alert data
        if not file_path.exists():
            rprint(f"[red]Error: File {file_path} does not exist[/red]")
            raise typer.Exit(1)
        
        with open(file_path, 'r') as f:
            alert_data = json.load(f)
        
        rprint(f"[blue]Processing alert from {file_path}...[/blue]")
        
        # Process alert
        import asyncio
        processed_alert = asyncio.run(
            alert_workflow.process_alert(alert_data, source)
        )
        
        # Display results
        display_processed_alert(processed_alert)
        
        # Save output if requested
        if output:
            save_processed_alert(processed_alert, output)
            rprint(f"[green]Results saved to {output}[/green]")
        
    except Exception as e:
        rprint(f"[red]Error processing alert: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def serve(
    host: str = typer.Option(settings.api_host, help="Server host"),
    port: int = typer.Option(settings.api_port, help="Server port"),
    reload: bool = typer.Option(settings.debug, help="Enable auto-reload"),
    log_level: str = typer.Option(settings.log_level, help="Log level")
):
    """Start the Alert Processing API server."""
    import uvicorn
    
    rprint(f"[blue]Starting Alert Processing Server on {host}:{port}[/blue]")
    rprint(f"[blue]Environment: {settings.environment}[/blue]")
    rprint(f"[blue]Log Level: {log_level}[/blue]")
    
    uvicorn.run(
        "alert_processing.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level=log_level.lower()
    )


@app.command()
def config():
    """Display current configuration."""
    table = Table(title="Alert Processing System Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="magenta")
    
    config_items = [
        ("App Name", settings.app_name),
        ("Version", settings.app_version),
        ("Environment", settings.environment),
        ("API Host", settings.api_host),
        ("API Port", str(settings.api_port)),
        ("Log Level", settings.log_level),
        ("Max Concurrent Alerts", str(settings.max_concurrent_alerts)),
        ("PII Anonymization", str(settings.pii_anonymization_enabled)),
        ("Database URL", settings.database_url),
        ("Redis URL", settings.redis_url if len(settings.redis_url) < 50 else settings.redis_url[:47] + "..."),
    ]
    
    for setting, value in config_items:
        table.add_row(setting, value)
    
    console.print(table)


@app.command()
def test_alert():
    """Generate and process a test alert."""
    test_data = {
        "data": {
            "context": {
                "name": "Test Alert",
                "description": "This is a test alert for system validation",
                "severity": "medium",
                "timestamp": "2024-01-01T12:00:00Z",
                "resourceName": "test-vm-001",
                "resourceGroupName": "test-rg",
                "resourceType": "virtualMachines",
                "subscriptionId": "12345678-1234-1234-1234-123456789012",
                "conditionType": "Metric",
                "monitorCondition": "Fired"
            }
        }
    }
    
    rprint("[blue]Processing test alert...[/blue]")
    
    try:
        import asyncio
        processed_alert = asyncio.run(
            alert_workflow.process_alert(test_data, "action_group")
        )
        
        display_processed_alert(processed_alert)
        
    except Exception as e:
        rprint(f"[red]Error processing test alert: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def version():
    """Display version information."""
    rprint(f"[blue]{settings.app_name}[/blue] v{settings.app_version}")
    rprint(f"Environment: {settings.environment}")


def display_processed_alert(processed_alert):
    """Display processed alert in a formatted table."""
    table = Table(title="Processed Alert Details")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="magenta")
    
    rows = [
        ("Alert ID", str(processed_alert.id)),
        ("Status", processed_alert.status.value),
        ("Category", processed_alert.category.value),
        ("Urgency Score", f"{processed_alert.urgency_score:.2f}"),
        ("Contains PII", str(processed_alert.contains_pii)),
        ("Processing Duration", f"{processed_alert.processing_duration:.2f}s" if processed_alert.processing_duration else "N/A"),
        ("Original Title", processed_alert.original_alert.title),
        ("Original Severity", processed_alert.original_alert.severity.value),
        ("Source", processed_alert.original_alert.source),
    ]
    
    if processed_alert.sentiment_score is not None:
        rows.append(("Sentiment Score", f"{processed_alert.sentiment_score:.2f}"))
    
    if processed_alert.impact_assessment:
        rows.append(("Impact Assessment", processed_alert.impact_assessment))
    
    if processed_alert.error_message:
        rows.append(("Error", processed_alert.error_message))
    
    for field, value in rows:
        table.add_row(field, value)
    
    console.print(table)
    
    # Display enrichment summary
    if processed_alert.enrichment_data:
        rprint("\n[blue]Enrichment Data Summary:[/blue]")
        for key, value in processed_alert.enrichment_data.items():
            if isinstance(value, dict) and "result_count" in value:
                rprint(f"  {key}: {value['result_count']} results")
            else:
                rprint(f"  {key}: {str(value)[:100]}...")


def save_processed_alert(processed_alert, output_path: Path):
    """Save processed alert to JSON file."""
    # Convert to dict for JSON serialization
    alert_dict = processed_alert.model_dump(mode='json')
    
    with open(output_path, 'w') as f:
        json.dump(alert_dict, f, indent=2, default=str)


def main():
    """Main entry point for CLI."""
    app()


if __name__ == "__main__":
    main()