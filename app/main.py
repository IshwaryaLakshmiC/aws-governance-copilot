from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import json, asyncio, os, uuid
from app.core.config import get_settings
from app.core.database import execute
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
    session_id: str | None = None


class CollectRequest(BaseModel):
    service: str = "all"  # all | iam | s3 | ec2 | guardduty | cloudtrail | cost


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "governance-copilot"}


@app.get("/api/stats")
async def get_account_stats():
    return get_stats()


@app.get("/api/findings")
async def get_findings(service: str = None, severity: str = None, limit: int = 50):
    return get_recent_findings(limit=limit, service=service)


@app.get("/api/costs")
async def get_costs():
    return get_cost_summary()


@app.post("/api/collect")
async def trigger_collection(req: CollectRequest):
    from app.collectors.aws_collectors import (
        collect_iam, collect_s3, collect_ec2,
        collect_guardduty, collect_cloudtrail, collect_cost_anomalies
    )
    collectors = {
        "iam": collect_iam, "s3": collect_s3, "ec2": collect_ec2,
        "guardduty": collect_guardduty, "cloudtrail": collect_cloudtrail,
        "cost": collect_cost_anomalies
    }
    loop = asyncio.get_event_loop()
    if req.service == "all":
        loop.run_in_executor(None, run_all_collectors)
    elif req.service in collectors:
        loop.run_in_executor(None, collectors[req.service])
    return {"status": "collection triggered", "service": req.service}


@app.post("/api/chat")
async def chat(req: ChatRequest):
    """Streaming chat — SSE. Persists conversation to RDS so a refresh
    or service restart doesn't lose the demo conversation."""
    session_id = req.session_id or str(uuid.uuid4())

    execute("""
        INSERT INTO governance_chat_history (session_id, role, content, created_at)
        VALUES (%s, 'user', %s, NOW())
    """, (session_id, req.question))

    async def generate():
        full_response = ""
        yield f"data: {json.dumps({'session_id': session_id})}\n\n"

        async for chunk in chat_engine.stream(req.question, req.history):
            full_response += chunk
            yield f"data: {json.dumps({'chunk': chunk})}\n\n"

        execute("""
            INSERT INTO governance_chat_history (session_id, role, content, created_at)
            VALUES (%s, 'assistant', %s, NOW())
        """, (session_id, full_response))

        yield f"data: {json.dumps({'done': True})}\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")


@app.get("/api/chat/{session_id}/history")
async def get_chat_history(session_id: str):
    """Retrieve a past conversation — survives restarts since it reads from RDS"""
    rows = execute("""
        SELECT role, content, created_at FROM governance_chat_history
        WHERE session_id = %s ORDER BY id ASC
    """, (session_id,), fetch=True)
    return {"session_id": session_id, "messages": rows}


# Serve frontend at /ui
frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_dir):
    app.mount("/ui", StaticFiles(directory=frontend_dir, html=True), name="frontend")

    @app.get("/")
    async def root():
        return FileResponse(os.path.join(frontend_dir, "index.html"))


@app.on_event("startup")
async def startup():
    """Skip auto-collection on startup — use demo data or trigger manually.
    Avoids crashing on startup if AWS credentials aren't configured locally."""
    print("Governance Copilot started. Use POST /api/collect to run collectors.")
    print("For local demo: run seed_demo_data.py first.")
