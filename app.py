import os
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"

# Custom dotenv loader to parse local env variables natively
if os.path.exists(".env"):
    with open(".env", "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                # Strip potential quote characters
                val_stripped = val.strip().strip("'").strip('"')
                os.environ[key.strip()] = val_stripped

import logging
from contextlib import asynccontextmanager
import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from dashboard.db import init_db
from dashboard.router import router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("cspm")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Modern lifecycle hook replacing deprecated on_event('startup')."""
    logger.info("Starting up AWS CSPM Application...")
    init_db()
    yield
    logger.info("Shutting down AWS CSPM Application.")

app = FastAPI(
    title="AWS CSPM Platform", 
    description="AWS Cloud Security Posture Management Dashboard",
    lifespan=lifespan
)

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register security check routes
app.include_router(router)

# Locate and mount static directory
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard", "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Catch-all route to serve the SPA
@app.get("/")
async def get_index():
    index_path = os.path.join(static_dir, "index.html")
    if not os.path.exists(index_path):
        # Return a quick fallback HTML if index.html isn't written yet
        from fastapi.responses import HTMLResponse
        return HTMLResponse("<h1>AWS CSPM Dashboard</h1><p>Frontend assets are being built.</p>", status_code=200)
    return FileResponse(index_path)

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
