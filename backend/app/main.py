# File: backend/app/main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.api.endpoints import auth, resources, cis_benchmark
import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/var/log/secops-backend.log', mode='a')
    ]
)

logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.APP_NAME,
    description="SecOps Multi-Tenant SaaS Application for AWS Resource Management",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Configuration - ALLOW ALL ORIGINS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)

# Include Routers
app.include_router(auth.router, prefix=f"{settings.API_V1_STR}/auth", tags=["Authentication"])
app.include_router(resources.router, prefix=f"{settings.API_V1_STR}/resources", tags=["Resources"])
app.include_router(cis_benchmark.router, prefix=f"{settings.API_V1_STR}/cis", tags=["CIS Benchmark"])

@app.on_event("startup")
async def startup_event():
    logger.info("=" * 50)
    logger.info("SecOps Backend Starting Up")
    logger.info(f"Environment: {settings.ENVIRONMENT}")
    logger.info(f"API Version: {settings.API_V1_STR}")
    logger.info(f"AWS Regions: {settings.AWS_REGIONS}")
    logger.info("=" * 50)

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("SecOps Backend Shutting Down")

@app.get("/")
async def root():
    return {
        "message": "SecOps API is running",
        "version": "1.0.0",
        "docs": "/docs"
    }

@app.get("/health")
async def health_check():
    logger.debug("Health check requested")
    return {
        "status": "healthy",
        "service": "secops-backend"
    }
