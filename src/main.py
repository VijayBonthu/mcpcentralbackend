from fastapi import FastAPI
import uvicorn
from dotenv import load_dotenv
import models
from models import engine
from fastapi.middleware.cors import CORSMiddleware
from routers import authentication, services
from utils.logger import setup_logger
from utils.rate_limit import lifespan
from utils.middleware import CSRFMiddleware, RateLimitMiddleware
from sqlalchemy import text
from contextlib import asynccontextmanager

# Setup logging once at application startup
logger = setup_logger()

load_dotenv()



app = FastAPI(lifespan=lifespan)

origins = [
    "http://localhost",
    "http://localhost:8080",
    "http://localhost:3000",
    "http://localhost:3001"

    # Add any other domains that need to access your API
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"], 
    allow_headers=["*"],
)

#order matters since there will be taken in sequence.
# app.add_middleware(RateLimitMiddleware)
# app.add_middleware(CSRFMiddleware)   

app.include_router(authentication.router, prefix="/api/v1", tags=["authentication"])
app.include_router(services.router, prefix="/api/v1", tags=["Services"])

@app.get("/")
def read_root():
    return {"Welcome to fastapi"}

if __name__ =="__main__":
    uvicorn.run('main:app', port=8080, reload=True)
         