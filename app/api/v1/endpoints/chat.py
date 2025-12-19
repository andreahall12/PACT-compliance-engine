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

# Configuration for the Gemara Server Binary
GEMARA_SERVER_PATH = BASE_DIR / "gemara-mcp-server" / "gemara-server"
GEMARA_SERVER_ARGS = []

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
        command=GEMARA_SERVER_PATH,
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
    query = """
    PREFIX pact: <http://your-org.com/ns/pact#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    PREFIX uco-obs: <https://ontology.unifiedcyberontology.org/uco/observable/>

    SELECT ?systemName ?processName ?controlName ?verdict ?assetName ?time (GROUP_CONCAT(?mappedReq; separator=", ") AS ?impactedFrameworks)
    WHERE {
        GRAPH ?g {
            ?assessment pact:hasVerdict ?verdict ;
                        pact:validatesControl ?control ;
                        pact:evaluatedEvidence ?ev ;
                        pact:generatedAt ?time .
            
            { ?ev uco-obs:fileName ?assetName } UNION { ?ev uco-obs:destinationPort ?assetName }
            
            ?system pact:hasComponent ?ev ;
                    rdfs:label ?systemName ;
                    pact:supports ?process .
                    
            ?process rdfs:label ?processName .
            ?control rdfs:label ?controlName .
        }
        OPTIONAL { ?control pact:satisfiesRequirement ?mappedReq . }
    }
    GROUP BY ?systemName ?processName ?controlName ?verdict ?assetName ?time
    ORDER BY DESC(?time)
    LIMIT 50
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

@router.post("/")
async def chat_with_auditor(payload: Dict[str, str] = Body(...)):
    question = payload.get("question")
    if not question:
        raise HTTPException(status_code=400, detail="No question provided")

    api_key = OPENAI_API_KEY
    ollama_host = OLLAMA_HOST
    model_name = AI_MODEL

    context_data = get_compliance_context()
    
    threat_sparql = """
    PREFIX pact: <http://your-org.com/ns/pact#>
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    SELECT ?vulnName ?controlName ?systemName ?verdict WHERE {
        ?control pact:mitigates ?vuln . ?vuln rdfs:label ?vulnName . ?control rdfs:label ?controlName .
        GRAPH ?g { ?assess pact:validatesControl ?control ; pact:hasVerdict ?verdict ; pact:evaluatedEvidence ?ev . ?system pact:hasComponent ?ev ; rdfs:label ?systemName . }
    } LIMIT 20
    """
    threat_results = db.query(threat_sparql)
    threat_data = []
    for row in threat_results:
        threat_data.append({
            "vulnerability": str(row.vulnName),
            "mitigated_by": str(row.controlName),
            "system": str(row.systemName),
            "status": str(row.verdict)
        })
    
    combined_context = {
        "compliance_failures": context_data,
        "threat_mitigations": threat_data
    }
    context_str = json.dumps(combined_context, indent=2)

    system_prompt = f"""
    You are an expert Security Compliance Auditor named 'PACT AI'.
    You have access to a semantic knowledge graph of the organization's security posture.
    
    CONTEXT DATA:
    {context_str}

    INSTRUCTIONS:
    - Answer based ONLY on the provided context.
    - If a system has failed a control, explain WHY and the IMPACT.
    - Be concise and professional.
    """

    # --- MCP Integration (Gemara) ---
    gemara_tools = []
    async with gemara_client() as gemara:
        if gemara:
            try:
                tools_list = await gemara.list_tools()
                gemara_tools = tools_list.tools
            except Exception as e:
                print(f"Error listing Gemara tools: {e}")

    if api_key and api_key.startswith("sk-"):
        if not OpenAI:
            return {"answer": "Error: OpenAI library not installed."}
        
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
        # Local AI via Ollama (HTTPX)
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

