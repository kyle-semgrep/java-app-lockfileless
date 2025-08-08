"""
Main FastAPI application for analytics collector service.
"""
from fastapi import FastAPI
from .api.collection import app as collection_app

app = FastAPI(
    title="Analytics Collector Service",
    description="Service for collecting and processing analytics data",
    version="1.0.0"
)

# Mount the collection API
app.mount("/", collection_app)