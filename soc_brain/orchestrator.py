# orchestrator.py
import json
import subprocess
import os
import logging
from typing import TypedDict, Optional
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import StateGraph, END
from event_store import store

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s', handlers=[logging.FileHandler("system.log"), logging.StreamHandler()], force=True)
logger = logging.getLogger('Orchestrator')

LLM_DRY_RUN = os.getenv("LLM_DRY_RUN", "True").lower() in ("true", "1", "yes", "t")

def get_llm():
    return ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0)

# ---------------------------------------------------------
# Asset Registry Mock Database
# ---------------------------------------------------------
asset_db = {
    "10.5.1.20": {"hostname": "dmz-web", "criticality": "Medium", "zone": "DMZ"},
    "10.5.2.20": {"hostname": "internal-db", "criticality": "Critical", "zone": "Internal Secure"},
    "10.5.2.30": {"hostname": "hr-portal", "criticality": "High", "zone": "Internal Secure"}
}

# Ensure the database is written on load so the tool can parse it safely
try:
    with open("asset_registry.json", "w") as f:
        json.dump(asset_db, f)
except Exception as e:
    logger.error(f"Failed to initialize asset registry: {e}")

# ---------------------------------------------------------
# Custom Tools (Python Functions)
# ---------------------------------------------------------
def lookup_asset(ip_address: str) -> str:
    try:
        with open("asset_registry.json", "r") as f:
            registry = json.load(f)
        asset_info = registry.get(ip_address)
        if asset_info:
            return f"Asset Found: Hostname: {asset_info['hostname']}, Criticality: {asset_info['criticality']}, Zone: {asset_info['zone']}"
        return f"Asset Not Found: The IP {ip_address} is unmapped or external."
    except Exception as e:
        return f"Database query failed: {str(e)}"

blocked_ips = set()

def block_ip(source_ip: str) -> str:
    try:
        # Check if the IP is already blocked
        if source_ip in blocked_ips:
            msg = f"INFO: IP {source_ip} is already blocked."
            store.add_mitigation({"target_ip": source_ip, "action": "Automated LangGraph Block", "status": "INFO", "message": msg})
            return msg

        check_cmd = ["iptables", "-C", "FORWARD", "-s", source_ip, "-j", "DROP"]
        if subprocess.run(check_cmd, capture_output=True).returncode == 0:
            blocked_ips.add(source_ip)
            msg = f"INFO: IP {source_ip} is already blocked."
            store.add_mitigation({"target_ip": source_ip, "action": "Automated LangGraph Block", "status": "INFO", "message": msg})
            return msg

        # Appends a DROP rule
        command = ["iptables", "-A", "FORWARD", "-s", source_ip, "-j", "DROP"]
        subprocess.run(command, check=True, capture_output=True, text=True)
        blocked_ips.add(source_ip)
        msg = f"SUCCESS: Iptables rule deployed. IP {source_ip} is now blocked at the routing layer."
        store.add_mitigation({"target_ip": source_ip, "action": "Automated LangGraph Block", "status": "SUCCESS", "message": msg})
        return msg
    except Exception as e:
        err = f"FAILED: System error during iptables execution: {str(e)}"
        store.add_mitigation({"target_ip": source_ip, "action": "Automated LangGraph Block", "status": "FAILED", "message": err})
        return err

# ---------------------------------------------------------
# LangGraph State & Nodes
# ---------------------------------------------------------
class AgentState(TypedDict):
    alert_data: dict
    triage_report: Optional[str]
    context_report: Optional[str]
    mitigation_status: Optional[str]

def triage_node(state: AgentState):
    store.add_flow_event({"step": "Triage", "status": "In Progress", "message": "Parsing raw ML flows..."})
    
    alert = state["alert_data"]
    attack_type = alert.get('attack_type', 'Unknown')
    
    if LLM_DRY_RUN:
        triage_content = f"**[DRY RUN] Triage Report:**\n- **Source:** {alert['source_ip']}\n- **Destination:** {alert['destination_ip']}\n- **Protocol:** {alert['protocol']}\n- **Traffic:** {alert['total_bytes']} bytes in {alert['duration_ms']} ms\n- **Analysis:** This flow matches the signature of a {attack_type} attack. ML Confidence is {(alert['confidence']*100):.1f}%."
    else:
        llm = get_llm()
        prompt = f"Analyze this network flow alert: {json.dumps(alert)}. Provide a short markdown triage report with Source, Destination, Protocol, Traffic, and Analysis."
        try:
            response = llm.invoke([HumanMessage(content=prompt)])
            triage_content = response.content
        except Exception as e:
            logger.error(f"LLM Error in Triage: {e}")
            triage_content = f"**[LLM ERROR] Triage Report:**\nFallback triggered. Flow matches {attack_type} attack."

    store.add_flow_event({"step": "Triage", "status": "Complete", "message": triage_content})
    return {"triage_report": triage_content}

def context_node(state: AgentState):
    store.add_flow_event({"step": "Context", "status": "In Progress", "message": "Querying asset registry..."})
    
    target_ip = state["alert_data"]["destination_ip"]
    context = lookup_asset(target_ip)
    
    if LLM_DRY_RUN:
        context_content = f"**[DRY RUN] Context Report:**\nTarget IP: {target_ip}\nRegistry Data: {context}\n- **Recommendation:** Immediate containment required to prevent resource exhaustion on targeted assets."
    else:
        llm = get_llm()
        prompt = f"Given this target IP: {target_ip} and this registry data: {context}. Provide a short markdown context report with recommendations for containment."
        try:
            response = llm.invoke([HumanMessage(content=prompt)])
            context_content = response.content
        except Exception as e:
            logger.error(f"LLM Error in Context: {e}")
            context_content = f"**[LLM ERROR] Context Report:**\nFallback triggered. Recommend immediate containment."

    store.add_flow_event({"step": "Context", "status": "Complete", "message": context_content})
    return {"context_report": context_content}

def response_node(state: AgentState):
    store.add_flow_event({"step": "Response", "status": "In Progress", "message": "Evaluating mitigation..."})
    
    if LLM_DRY_RUN:
        decision = "BLOCK"
    else:
        llm = get_llm()
        prompt = f"Based on the triage report: {state['triage_report']} and context report: {state['context_report']}, should we BLOCK the source IP {state['alert_data']['source_ip']}? Respond with only 'BLOCK' or 'IGNORE'."
        try:
            response = llm.invoke([HumanMessage(content=prompt)])
            decision = response.content.strip()
        except Exception as e:
            logger.error(f"LLM Error in Response: {e}")
            decision = "BLOCK"

    if "BLOCK" in decision.upper():
        store.add_flow_event({"step": "Response", "status": "Executing", "message": "Threat confirmed. Deploying iptables DROP rule."})
        result = block_ip(state['alert_data']['source_ip'])
    else:
        result = "Asset not critical. Mitigation bypassed."
        store.add_flow_event({"step": "Response", "status": "Bypassed", "message": result})
        
    store.add_flow_event({"step": "Response", "status": "Complete", "message": result})
    return {"mitigation_status": result}

# Build Graph
workflow = StateGraph(AgentState)
workflow.add_node("triage", triage_node)
workflow.add_node("context", context_node)
workflow.add_node("response", response_node)

workflow.set_entry_point("triage")
workflow.add_edge("triage", "context")
workflow.add_edge("context", "response")
workflow.add_edge("response", END)

app_graph = workflow.compile()

import time
last_execution_time = 0
COOLDOWN_PERIOD = 30 # seconds

def trigger_swarm(alert_data: dict):
    global last_execution_time
    
    source_ip = alert_data.get('source_ip')
    if source_ip in blocked_ips:
        logger.info(f"Skipping LangGraph execution. Source IP {source_ip} is already blocked.")
        store.add_flow_event({"step": "Rate Limit", "status": "Bypassed", "message": f"LLM execution skipped. Source IP {source_ip} was already permanently mitigated."})
        return
        
    current_time = time.time()
    if current_time - last_execution_time < COOLDOWN_PERIOD:
        logger.info(f"Skipping LangGraph execution. Cooldown active for {COOLDOWN_PERIOD - (current_time - last_execution_time):.1f}s to prevent API flooding.")
        store.add_flow_event({"step": "Rate Limit", "status": "Bypassed", "message": "LLM API call skipped due to active 30s cooldown."})
        return
        
    last_execution_time = current_time
    
    logger.info("Initializing LangGraph AI Flow...")
    store.add_flow_event({"step": "Detection", "status": "Complete", "message": f"Anomaly Detected: {alert_data['confidence']*100:.2f}% confidence."})
    
    try:
        initial_state = {
            "alert_data": alert_data,
            "triage_report": None,
            "context_report": None,
            "mitigation_status": None
        }
        
        final_state = app_graph.invoke(initial_state)
        
        logger.info(f"LangGraph execution complete. Final Status: {final_state['mitigation_status']}")
    except Exception as e:
        logger.error(f"Error during LangGraph execution: {e}")
        store.add_flow_event({"step": "System Error", "status": "Failed", "message": str(e)})
