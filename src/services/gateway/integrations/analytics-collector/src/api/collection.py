"""
Analytics collection endpoints with SSRF false positives.
All endpoints use runtime URL validation that SAST cannot detect.
"""
import aiohttp
from fastapi import FastAPI, Query, Path, Body
from typing import Optional, Dict, Any
from ..security.url_validator import UrlValidator

app = FastAPI()


@app.post("/api/v1/analytics/events/collect")
async def collect_analytics_events(
    event_endpoint: str = Query(..., description="Analytics event collection endpoint"),
    source: Optional[str] = Query(None)
):
    """Collect analytics events from external endpoint."""
    
    safe_url = UrlValidator.sanitize_url(event_endpoint)
    
    async with aiohttp.ClientSession() as session:
        async with session.post(safe_url, json={"source": source}) as response:
            return {"status": "collected", "code": response.status}


@app.get("/api/v1/analytics/metrics/fetch/{provider}")
async def fetch_metrics_from_provider(
    provider: str = Path(...),
    metrics_url: str = Query(..., description="Metrics API endpoint")
):
    """Fetch metrics from external analytics provider."""
    validated_url = UrlValidator.validate_and_clean_url(metrics_url)
    
    session = aiohttp.ClientSession()
    try:
        
        response = await session.get(validated_url, params={"provider": provider})
        data = await response.text()
        return {"metrics": data, "provider": provider}
    finally:
        await session.close()