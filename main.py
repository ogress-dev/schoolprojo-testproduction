from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import create_tables
from routers import scans

# Create database tables
create_tables()

app = FastAPI(
    title="URL Scanner API",
    description="FastAPI backend for URL scanning and classification",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scans.router, prefix="/api", tags=["scans"])

@app.get("/")
async def root():
    return {"message": "URL Scanner API", "version": "1.0.0"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}