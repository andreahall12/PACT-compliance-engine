from fastapi import APIRouter, HTTPException, Body
from typing import Dict
import json
import os
import httpx
from contextlib import asynccontextmanager
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from app.core.store import db
from app.core.config import BASE_DIR, OPENAI_API_KEY, OLLAMA_HOST, AI_MODEL

router = APIRouter()

# =============================================================================
# Constants
# =============================================================================

# Configuration for the Gemara Server Binary
GEMARA_SERVER_PATH = BASE_DIR / "gemara-mcp-server" / "gemara-server"
GEMARA_SERVER_ARGS = []

# Query limits
COMPLIANCE_CONTEXT_LIMIT = 25
THREAT_CONTEXT_LIMIT = 10

# SPARQL Prefixes (shared with compliance.py)
SPARQL_PREFIXES = """
PREFIX pact: <http://your-org.com/ns/pact#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX uco-obs: <https://ontology.unifiedcyberontology.org/uco/observable/>
"""

# Usage documentation for "how do I" questions
USAGE_DOCS = """
## PACT Usage Guide

### Dashboard
- Shows real-time compliance posture across all systems
- **Critical Failures** table lists controls that failed with evidence links
- **Configuration Drift** shows systems that went from PASS to FAIL
- Click any row to see details

### Simulating Events
1. Select a System from the dropdown (e.g., "PaymentGatewayCluster")
2. Select one or more Frameworks (e.g., "NIST AC-3")
3. Click "Simulate Event" and choose:
   - **Successful Login** - creates a PASS event
   - **Root File Access** - creates a FAIL event
4. Click "Refresh Dashboard" to see the new data

### Blast Radius
- Shows the impact of compliance failures
- Visual diagram: Failed Control → Affected Systems → Business Processes
- Helps prioritize remediation by business impact

### Configuration Drift
- Timeline view of when systems drifted from compliant to non-compliant
- Detail cards show: WHAT changed, WHEN, WHO (if known), and WHY (violation message)
- "Ask AI" button lets you query specific drift events

### AI Auditor (this chat)
- Ask compliance questions: "Why did PaymentGateway fail?"
- Ask impact questions: "What's affected by the firewall issue?"
- Ask usage questions: "How do I export a report?"

### Common Tasks
- **View evidence**: Click the external link icon on any failure row
- **Filter by framework**: Use the Framework dropdown on Dashboard
- **Check specific system**: Use the System dropdown, then Refresh
"""

def detect_intent(question: str) -> str:
    """Detect if user is asking about PACT usage vs compliance data."""
    question_lower = question.lower()
    
    usage_keywords = [
        "how do i", "how can i", "how to", "where is", "where do i",
        "what does", "what is the", "help me", "show me how",
        "tutorial", "guide", "button", "click", "navigate",
        "use this", "use the", "get started", "simulate", "export"
    ]
    
    for keyword in usage_keywords:
        if keyword in question_lower:
            return "usage"
    
    return "compliance"

# OpenAI Setup
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

@asynccontextmanager
async def gemara_client():
    if not os.path.exists(GEMARA_SERVER_PATH):
        yield None
        return
        
    server_params = StdioServerParameters(
        command=str(GEMARA_SERVER_PATH),
        args=GEMARA_SERVER_ARGS,
        env=None
    )
    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                yield session
    except Exception as e:
        print(f"MCP Connection Error: {e}")
        yield None

def get_compliance_context():
    query = SPARQL_PREFIXES + f"""
    SELECT ?systemName ?processName ?controlName ?verdict ?assetName ?time (GROUP_CONCAT(?mappedReq; separator=", ") AS ?impactedFrameworks)
    WHERE {{
        GRAPH ?g {{
            ?assessment pact:hasVerdict ?verdict ;
                        pact:validatesControl ?control ;
                        pact:evaluatedEvidence ?ev ;
                        pact:generatedAt ?time .
            
            {{ ?ev uco-obs:fileName ?assetName }} UNION {{ ?ev uco-obs:destinationPort ?assetName }}
            
            ?system pact:hasComponent ?ev ;
                    rdfs:label ?systemName ;
                    pact:supports ?process .
                    
            ?process rdfs:label ?processName .
            ?control rdfs:label ?controlName .
        }}
        OPTIONAL {{ ?control pact:satisfiesRequirement ?mappedReq . }}
    }}
    GROUP BY ?systemName ?processName ?controlName ?verdict ?assetName ?time
    ORDER BY DESC(?time)
    LIMIT {COMPLIANCE_CONTEXT_LIMIT}
    """
    results = db.query(query)
    context_data = []
    for row in results:
        context_data.append({
            "timestamp": str(row.time),
            "system": str(row.systemName),
            "process": str(row.processName),
            "control": str(row.controlName),
            "status": str(row.verdict),
            "asset": str(row.assetName),
            "impacted_frameworks": str(row.impactedFrameworks) if row.impactedFrameworks else "None"
        })
    return context_data

@router.post("")
async def chat_with_auditor(payload: Dict[str, str] = Body(...)):
    question = payload.get("question")
    if not question:
        raise HTTPException(status_code=400, detail="No question provided")
    if len(question) > 4000:
        raise HTTPException(status_code=400, detail="Question too long (max 4000 chars)")

    api_key = OPENAI_API_KEY
    ollama_host = OLLAMA_HOST
    model_name = AI_MODEL

    # Detect intent and build appropriate context
    intent = detect_intent(question)
    
    if intent == "usage":
        # Usage questions get the documentation context
        system_prompt = f"""You are PACT AI, a helpful assistant for the PACT compliance tool.
The user is asking how to use the tool.

PACT DOCUMENTATION:
{USAGE_DOCS}

INSTRUCTIONS:
- Answer the user's question about how to use PACT
- Be concise and give step-by-step instructions when appropriate
- If you're not sure, say so and suggest they check the user guide
"""
    else:
        # Compliance questions get the graph context
        context_data = get_compliance_context()
        
        threat_sparql = SPARQL_PREFIXES + f"""
        SELECT ?vulnName ?controlName ?systemName ?verdict WHERE {{
            ?control pact:mitigates ?vuln . ?vuln rdfs:label ?vulnName . ?control rdfs:label ?controlName .
            GRAPH ?g {{ ?assess pact:validatesControl ?control ; pact:hasVerdict ?verdict ; pact:evaluatedEvidence ?ev . ?system pact:hasComponent ?ev ; rdfs:label ?systemName . }}
        }} LIMIT {THREAT_CONTEXT_LIMIT}
        """
        threat_results = db.query(threat_sparql)
        threat_data = [
            {
                "vulnerability": str(row.vulnName),
                "mitigated_by": str(row.controlName),
                "system": str(row.systemName),
                "status": str(row.verdict)
            }
            for row in threat_results
        ]
        
        combined_context = {
            "compliance_failures": context_data,
            "threat_mitigations": threat_data
        }
        context_str = json.dumps(combined_context, indent=2)

        system_prompt = f"""You are an expert Security Compliance Auditor named 'PACT AI'.
You have access to a semantic knowledge graph of the organization's security posture.

CONTEXT DATA:
{context_str}

INSTRUCTIONS:
- Answer based ONLY on the provided context.
- If a system has failed a control, explain WHY and the IMPACT.
- Be concise and professional.
"""

    # --- AI Provider Routing ---
    if api_key and api_key.startswith("sk-"):
        # 1. OpenAI MODE (with Gemara Tools)
        if not OpenAI:
            return {"answer": "Error: OpenAI library not installed."}
        
        # Discover Tools
        gemara_tools = []
        async with gemara_client() as gemara:
            if gemara:
                try:
                    tools_list = await gemara.list_tools()
                    gemara_tools = tools_list.tools
                except Exception as e:
                    print(f"Error listing Gemara tools: {e}")

        client = OpenAI(api_key=api_key)
        openai_tools = [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.inputSchema
                }
            } for t in gemara_tools
        ]

        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": question}
            ]
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=messages,
                tools=openai_tools if openai_tools else None
            )
            
            # Handle Tool Calls if any
            response_msg = response.choices[0].message
            if response_msg.tool_calls:
                messages.append(response_msg)
                async with gemara_client() as gemara:
                    if gemara:
                        for tool_call in response_msg.tool_calls:
                            result = await gemara.call_tool(tool_call.function.name, json.loads(tool_call.function.arguments))
                            messages.append({
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "content": str(result.content)
                            })
                
                final_response = client.chat.completions.create(model="gpt-4o", messages=messages)
                return {"answer": final_response.choices[0].message.content}

            return {"answer": response_msg.content}
        except Exception as e:
            return {"answer": f"Error calling OpenAI: {str(e)}"}
            
    else:
        # 2. LOCAL OLLAMA MODE (Direct & Fast)
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                ollama_response = await client.post(
                    f"{ollama_host}/chat/completions",
                    json={
                        "model": model_name,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": question}
                        ],
                        "stream": False
                    }
                )
                if ollama_response.status_code != 200:
                    return {"answer": f"Ollama Error {ollama_response.status_code}: {ollama_response.text}"}
                data = ollama_response.json()
                return {"answer": data["choices"][0]["message"]["content"]}
        except Exception as e:
            return {"answer": f"Error calling Local AI: {str(e)}"}

