"""
AWS Automated Incident Response Agent
LangGraph ReAct agent that investigates CloudWatch alarms and returns a
PROBLEM / EVIDENCE / FIX report via Amazon Bedrock (Claude 3 Sonnet).

Required environment variables:
  AWS_REGION          - AWS region for Bedrock (default: us-east-1)
  BEDROCK_MODEL_ID    - Bedrock model ID (default: anthropic.claude-3-5-sonnet-20241022-v2:0)
  PORT                - Port to listen on (default: 8080)
"""

import os
import json
import logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from langchain_aws import ChatBedrockConverse
from langgraph.prebuilt import create_react_agent
from tools.generic import aws_api_call

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
REGION = os.environ.get("AWS_REGION", "us-east-1")
MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    "anthropic.claude-3-5-sonnet-20241022-v2:0"
)
PORT = int(os.environ.get("PORT", "8080"))

# ── Bedrock LLM ───────────────────────────────────────────────────────────────
llm = ChatBedrockConverse(
    model=MODEL_ID,
    region_name=REGION,
    temperature=0,
    max_tokens=8192,
)

# ── Tools ─────────────────────────────────────────────────────────────────────
tools = [aws_api_call]

# ── System prompt ─────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are an AWS incident response agent.

Your job is to investigate AWS infrastructure incidents by calling AWS APIs,
identify the root cause, and return a structured report.

ALWAYS respond in this exact format:

PROBLEM
<one sentence: what broke and why>

EVIDENCE
- <timestamp>: <what happened>
- <timestamp>: <what happened>
- <key metric or state>

FIX
<exact AWS CLI command or console action to restore service>

Rules:
- Only consider CloudTrail events from the last 2 hours as root cause
- Check Palo Alto ENIC first (EC2 instance state, SG, route tables)
- Then check infrastructure (NLB/ALB, VPC endpoints)
- Then check compute (ECS desiredCount, EC2 state)
- Then check application health (exit codes, logs, CPU/memory)
- Finally check CloudTrail for who made changes
- Never speculate — only report what AWS APIs confirm
- Never include confidence scores or model disclaimers
- The FIX must be a concrete, executable command
"""

# ── LangGraph agent ───────────────────────────────────────────────────────────
graph = create_react_agent(llm, tools=tools, prompt=SYSTEM_PROMPT)

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(title="AWS Incident Response Agent")


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.post("/investigate")
async def investigate(request: Request):
    body = await request.json()
    prompt = body.get("prompt", "")
    if not prompt:
        return JSONResponse({"error": "prompt is required"}, status_code=400)

    logger.info("Starting investigation...")
    try:
        result = graph.invoke({"messages": [("human", prompt)]})
        final_message = result["messages"][-1].content
        logger.info("Investigation complete.")
        return {"result": final_message}
    except Exception as e:
        logger.error(f"Investigation failed: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
