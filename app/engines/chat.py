"""
Chat Engine — natural language queries over real AWS findings.
Uses pgvector for semantic search + Claude for reasoning.
"""

import json
import boto3
import numpy as np
from typing import AsyncGenerator
from app.core.llm import LLMClient
from app.core.database import execute
from app.core.config import get_settings

settings = get_settings()

SYSTEM_PROMPT = """You are an expert AWS Security and Cost Governance analyst.
You have access to real findings collected from the customer's AWS account.

Your job:
- Answer questions about their AWS security posture, costs, and compliance
- Ground every answer in the actual findings provided
- Cite specific resource IDs, user names, and finding details
- Prioritise by severity and business impact
- Suggest specific remediation steps with AWS CLI commands where helpful
- Be direct and concise — security teams are busy

If findings don't contain the information needed, say so clearly.
Never make up findings or resource names.

Format:
- Lead with the direct answer
- Support with specific finding details
- End with prioritised next steps"""


def get_embedding(text: str) -> list[float]:
    """Get vector embedding using Amazon Titan Embeddings V2 via Bedrock"""
    bedrock = boto3.client("bedrock-runtime", region_name=settings.aws_region)
    resp = bedrock.invoke_model(
        modelId=settings.bedrock_embedding_model_id,
        body=json.dumps({"inputText": text[:8000]}),
        contentType="application/json",
        accept="application/json"
    )
    return json.loads(resp["body"].read())["embedding"]


def search_findings(query: str, service: str = None, severity: str = None, limit: int = 10) -> list[dict]:
    """Semantic search over findings using pgvector cosine similarity"""
    try:
        embedding = get_embedding(query)
        embedding_str = "[" + ",".join(str(x) for x in embedding) + "]"

        where_clauses = ["embedding IS NOT NULL"]
        params = []

        if service:
            where_clauses.append("service = %s")
            params.append(service)
        if severity:
            where_clauses.append("severity = %s")
            params.append(severity)

        where = " AND ".join(where_clauses)
        params.extend([embedding_str, limit])

        results = execute(f"""
            SELECT finding_id, service, severity, title, description,
                   resource_id, region, collected_at,
                   1 - (embedding <=> %s::vector) as similarity
            FROM findings
            WHERE {where}
            ORDER BY embedding <=> %s::vector
            LIMIT %s
        """, params + [embedding_str, embedding_str, limit], fetch=True)
        return results or []
    except Exception:
        # Fallback: keyword search if embeddings not yet populated
        params = []
        where = "1=1"
        if service:
            where += " AND service = %s"
            params.append(service)
        if severity:
            where += " AND severity = %s"
            params.append(severity)
        params.append(limit)
        return execute(f"SELECT * FROM findings WHERE {where} ORDER BY collected_at DESC LIMIT %s",
                      params, fetch=True) or []


def get_recent_findings(limit: int = 20, service: str = None) -> list[dict]:
    """Get most recent findings, optionally filtered by service"""
    params = []
    where = "1=1"
    if service:
        where += " AND service = %s"
        params.append(service)
    params.append(limit)
    return execute(
        f"SELECT * FROM findings WHERE {where} ORDER BY collected_at DESC LIMIT %s",
        params, fetch=True
    ) or []


def get_cost_summary() -> list[dict]:
    return execute(
        "SELECT * FROM cost_anomalies ORDER BY amount_usd DESC LIMIT 20",
        fetch=True
    ) or []


def get_stats() -> dict:
    stats = execute("""
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
            COUNT(DISTINCT service) as services_scanned,
            MAX(collected_at) as last_collected
        FROM findings
    """, fetch=True)
    return stats[0] if stats else {}


class ChatEngine:
    def __init__(self):
        self.llm = LLMClient()

    async def stream(self, question: str, history: list[dict]) -> AsyncGenerator[str, None]:
        """Stream a response to a natural language security question"""

        # Detect intent to optimise retrieval
        q_lower = question.lower()
        service_hint = None
        if any(w in q_lower for w in ["iam", "user", "role", "permission", "mfa", "access key"]):
            service_hint = "iam"
        elif any(w in q_lower for w in ["s3", "bucket", "storage", "object"]):
            service_hint = "s3"
        elif any(w in q_lower for w in ["ec2", "instance", "security group", "port"]):
            service_hint = "ec2"
        elif any(w in q_lower for w in ["guardduty", "threat", "malicious", "tor"]):
            service_hint = "guardduty"
        elif any(w in q_lower for w in ["cost", "bill", "spend", "dollar", "expensive", "nat"]):
            service_hint = "cost"
        elif any(w in q_lower for w in ["cloudtrail", "api call", "who called", "audit"]):
            service_hint = "cloudtrail"

        # Retrieve relevant findings
        relevant = search_findings(question, service=service_hint, limit=8)
        recent = get_recent_findings(limit=5)
        cost = get_cost_summary() if "cost" in q_lower or "bill" in q_lower else []
        stats = get_stats()

        # Build context
        context_parts = []
        if stats:
            context_parts.append(f"ACCOUNT SUMMARY: {stats.get('total',0)} total findings "
                                 f"({stats.get('critical',0)} critical, {stats.get('high',0)} high) "
                                 f"across {stats.get('services_scanned',0)} services. "
                                 f"Last collected: {stats.get('last_collected','unknown')}")

        if relevant:
            context_parts.append("RELEVANT FINDINGS:\n" + "\n".join([
                f"[{f['severity'].upper()}] {f['title']} | Resource: {f['resource_id']} | Service: {f['service']}"
                + (f"\n  Details: {f['description']}" if f.get('description') else "")
                for f in relevant
            ]))

        if cost:
            context_parts.append("COST DATA (top items):\n" + "\n".join([
                f"${c['amount_usd']:.2f} — {c['service']} on {c['anomaly_date']}"
                for c in cost[:5]
            ]))

        context = "\n\n".join(context_parts) or "No findings collected yet. Run collectors first."

        messages = history[-6:] + [{"role": "user", "content":
            f"Context from AWS account:\n{context}\n\nQuestion: {question}"}]

        async for chunk in self.llm.stream(SYSTEM_PROMPT, messages):
            yield chunk
