import os
import sys
import argparse
from rdflib import Dataset, Namespace

# Check for OpenAI key
api_key = os.getenv("OPENAI_API_KEY")

try:
    from openai import OpenAI
except ImportError:
    print("Error: 'openai' module not found. Run: venv/bin/pip install openai")
    sys.exit(1)

# CLI
parser = argparse.ArgumentParser(description='PACT AI Auditor')
parser.add_argument('question', type=str, nargs='?', help='The question to ask the auditor')
args = parser.parse_args()

if not args.question:
    print("\n👋 I am your PACT AI Auditor.")
    print("   I have read your compliance graph and can answer questions about failures, blast radius, and drift.")
    print("   Usage: python3 ai_auditor.py \"Why did the HR System fail?\"\n")
    args.question = input(">> What would you like to know? ")

# 1. Load the Graph Data
print(" ... Loading Knowledge Graph (this may take a moment) ...")
ds = Dataset()
try:
    ds.parse("pact_history.trig", format="trig")
except Exception as e:
    print(f"Error loading graph: {e}")
    sys.exit(1)

# 2. Extract Context (The "RAG" part)
# We run a broad query to get the current state of the world to feed the LLM.
# In a real app, we'd only fetch relevant sub-graphs based on the user's query keywords.
query = """
PREFIX pact: <http://your-org.com/ns/pact#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX uco-obs: <https://ontology.unifiedcyberontology.org/uco/observable/>

SELECT ?systemName ?processName ?controlName ?verdict ?assetName ?time
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
}
ORDER BY DESC(?time)
LIMIT 50
"""

results = ds.query(query)
context_data = []

for row in results:
    context_data.append({
        "timestamp": str(row.time),
        "system": str(row.systemName),
        "process": str(row.processName),
        "control": str(row.controlName),
        "status": str(row.verdict),
        "asset": str(row.assetName)
    })

context_str = str(context_data)

# 3. Call LLM
if not api_key:
    print("\n⚠️  No OPENAI_API_KEY found in environment variables.")
    print("   I cannot call the AI directly, but here is the context I extracted from the graph:\n")
    print(context_str[:500] + "..." if len(context_str) > 500 else context_str)
    print("\n   [Copy the above + your question into ChatGPT]")
    sys.exit(0)

client = OpenAI(api_key=api_key)

print(" ... Thinking ...")

system_prompt = f"""
You are an expert Security Compliance Auditor named 'PACT AI'.
You have access to a semantic knowledge graph of the organization's security posture.
The current state of the graph (recent assessments) is provided below in JSON format.

CONTEXT DATA:
{context_str}

INSTRUCTIONS:
- Answer the user's question based ONLY on the provided context.
- If a system has failed a control, explain WHY (the asset involved) and the IMPACT (the business process).
- If the user asks about 'Drift', look for assets that have both PASS and FAIL records at different times.
- Be concise and professional.
"""

try:
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": args.question}
        ]
    )
    
    answer = response.choices[0].message.content
    print("\n🤖 PACT AI Auditor:")
    print("-" * 60)
    print(answer)
    print("-" * 60)

except Exception as e:
    print(f"Error calling OpenAI: {e}")

