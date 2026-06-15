from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel
import json, asyncio
from app.core.config import get_settings
from app.engines.chat import ChatEngine, get_stats, get_recent_findings, get_cost_summary
from app.collectors.aws_collectors import run_all_collectors

settings = get_settings()
chat_engine = ChatEngine()

app = FastAPI(title="AWS Governance Copilot", version="1.0.0", docs_url="/api/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ChatRequest(BaseModel):
    question: str
    history: list[dict] = []


class CollectRequest(BaseModel):
    service: str = "all"  # all | iam | s3 | ec2 | guardduty | cloudtrail | cost


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "governance-copilot"}


@app.get("/api/stats")
async def get_account_stats():
    """Summary stats for the dashboard"""
    return get_stats()


@app.get("/api/findings")
async def get_findings(service: str = None, severity: str = None, limit: int = 50):
    """Get recent findings, optionally filtered"""
    return get_recent_findings(limit=limit, service=service)


@app.get("/api/costs")
async def get_costs():
    """Get cost anomalies"""
    return get_cost_summary()


@app.post("/api/collect")
async def trigger_collection(req: CollectRequest):
    """Trigger a collection run (async — returns immediately)"""
    from app.collectors.aws_collectors import (
        collect_iam, collect_s3, collect_ec2,
        collect_guardduty, collect_cloudtrail, collect_cost_anomalies
    )
    collectors = {
        "iam": collect_iam, "s3": collect_s3, "ec2": collect_ec2,
        "guardduty": collect_guardduty, "cloudtrail": collect_cloudtrail,
        "cost": collect_cost_anomalies
    }
    if req.service == "all":
        asyncio.get_event_loop().run_in_executor(None, run_all_collectors)
    elif req.service in collectors:
        asyncio.get_event_loop().run_in_executor(None, collectors[req.service])
    return {"status": "collection triggered", "service": req.service}


@app.post("/api/chat")
async def chat(req: ChatRequest):
    """Streaming chat endpoint — SSE"""
    async def generate():
        async for chunk in chat_engine.stream(req.question, req.history):
            yield f"data: {json.dumps({'chunk': chunk})}\n\n"
        yield f"data: {json.dumps({'done': True})}\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")


@app.on_event("startup")
async def startup():
    """Run initial collection on startup"""
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, run_all_collectors)
