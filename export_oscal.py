import uuid
import datetime
import json
from rdflib import Graph, Namespace

# 1. Load the PACT Graph (The output from your engine)
# In a real app, you would load the file saved by pact_engine.py
# For now, we will simulate the graph having one failure.

PACT = Namespace("http://your-org.com/ns/pact#")
UCO_OBS = Namespace("https://ontology.unifiedcyberontology.org/uco/observable/")

# 2. Define the Template for an OSCAL "Observation"
# This is the standard format ComplyTime expects for a "Finding".
def create_oscal_observation(control_id, description, status):
    return {
        "uuid": str(uuid.uuid4()),
        "title": f"Automated Assessment of {control_id}",
        "description": description,
        "methods": ["TEST"],
        "types": ["finding"],
        "subjects": [
            {
                "subject-uuid": str(uuid.uuid4()),
                "type": "component",
                "title": "Linux Server Configuration"
            }
        ],
        "relevant-evidence": [
            {
                "href": "./raw_event.json",
                "description": "OCSF Log File from Splunk"
            }
        ],
        "collected": datetime.datetime.now().isoformat() + "Z",
        "observation-status": status  # "satisfied" or "not-satisfied"
    }

# 3. The Translator Logic
print("--- Exporting PACT Results to OSCAL ---")

# (Simulate reading the verdict from your graph - simpler for this demo)
# In the real script, we query the graph just like in 'generate_report.py'
pact_verdict = "FAIL" 
control_id = "ac-6"
evidence_detail = "File 'sensitive_config.yaml' is owned by 'root'"

# Map PACT "FAIL" to OSCAL "not-satisfied"
oscal_status = "not-satisfied" if pact_verdict == "FAIL" else "satisfied"

# 4. Generate the JSON
oscal_output = {
    "assessment-results": {
        "uuid": str(uuid.uuid4()),
        "metadata": {
            "title": "PACT Automated Compliance Scan",
            "last-modified": datetime.datetime.now().isoformat() + "Z",
            "version": "1.0.0",
            "oscal-version": "1.1.2"
        },
        "results": [
            {
                "uuid": str(uuid.uuid4()),
                "title": "Daily Compliance Run",
                "observations": [
                    create_oscal_observation(control_id, evidence_detail, oscal_status)
                ]
            }
        ]
    }
}

# 5. Save to File
filename = "pact_oscal_results.json"
with open(filename, "w") as f:
    json.dump(oscal_output, f, indent=2)

print(f"✅ Success! Generated OSCAL artifact: {filename}")
print("   (This file can now be imported into ComplyTime)")