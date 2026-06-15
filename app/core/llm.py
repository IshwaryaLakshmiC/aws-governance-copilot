import boto3
import json
import httpx
from typing import AsyncGenerator
from app.core.config import get_settings

settings = get_settings()


class LLMClient:
    def __init__(self):
        self.bedrock = boto3.client("bedrock-runtime", region_name=settings.aws_region)

    async def complete(self, system: str, messages: list[dict], max_tokens: int = 2000) -> str:
        try:
            return await self._bedrock_complete(system, messages, max_tokens)
        except Exception as e:
            print(f"Bedrock failed ({e}), falling back to OpenRouter")
            return await self._openrouter_complete(system, messages, max_tokens)

    async def stream(self, system: str, messages: list[dict], max_tokens: int = 2000) -> AsyncGenerator[str, None]:
        try:
            async for chunk in self._bedrock_stream(system, messages, max_tokens):
                yield chunk
        except Exception as e:
            print(f"Bedrock stream failed ({e}), falling back to OpenRouter")
            async for chunk in self._openrouter_stream(system, messages, max_tokens):
                yield chunk

    async def _bedrock_complete(self, system, messages, max_tokens) -> str:
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "system": system,
            "messages": messages,
            "temperature": 0.2,
        })
        resp = self.bedrock.invoke_model(
            modelId=settings.bedrock_model_id,
            body=body,
            contentType="application/json",
            accept="application/json"
        )
        return json.loads(resp["body"].read())["content"][0]["text"]

    async def _bedrock_stream(self, system, messages, max_tokens) -> AsyncGenerator[str, None]:
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "system": system,
            "messages": messages,
            "temperature": 0.2,
        })
        resp = self.bedrock.invoke_model_with_response_stream(
            modelId=settings.bedrock_model_id,
            body=body,
            contentType="application/json",
            accept="application/json"
        )
        for event in resp.get("body"):
            chunk = event.get("chunk")
            if chunk:
                data = json.loads(chunk["bytes"])
                if data.get("type") == "content_block_delta":
                    yield data.get("delta", {}).get("text", "")

    async def _openrouter_complete(self, system, messages, max_tokens) -> str:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={"Authorization": f"Bearer {settings.openrouter_api_key}",
                         "HTTP-Referer": "https://ishwaryaaunfiltered.live"},
                json={"model": settings.openrouter_model, "max_tokens": max_tokens,
                      "messages": [{"role": "system", "content": system}] + messages},
                timeout=60.0
            )
            return resp.json()["choices"][0]["message"]["content"]

    async def _openrouter_stream(self, system, messages, max_tokens) -> AsyncGenerator[str, None]:
        async with httpx.AsyncClient() as client:
            async with client.stream(
                "POST", "https://openrouter.ai/api/v1/chat/completions",
                headers={"Authorization": f"Bearer {settings.openrouter_api_key}",
                         "HTTP-Referer": "https://ishwaryaaunfiltered.live"},
                json={"model": settings.openrouter_model, "max_tokens": max_tokens, "stream": True,
                      "messages": [{"role": "system", "content": system}] + messages},
                timeout=60.0
            ) as resp:
                async for line in resp.aiter_lines():
                    if line.startswith("data: ") and line != "data: [DONE]":
                        try:
                            data = json.loads(line[6:])
                            content = data["choices"][0].get("delta", {}).get("content", "")
                            if content:
                                yield content
                        except Exception:
                            pass
