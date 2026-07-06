# orchestrator.py
import json
import subprocess
import os
import time
import logging
import threading
from typing import TypedDict, Optional
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import create_react_agent
from event_store import store

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s', handlers=[logging.FileHandler("system.log"), logging.StreamHandler()], force=True)
logger = logging.getLogger('Orchestrator')

LLM_DRY_RUN = os.getenv("LLM_DRY_RUN", "True").lower() in ("true", "1", "yes", "t")

# Reuse a single client instead of constructing one per node call, and bound
# every call with a timeout/retry policy so a hung Gemini request can't stall
# a detection thread forever.
_llm_singleton = None

def get_llm():
    global _llm_singleton
    if _llm_singleton is None:
        _llm_singleton = ChatGoogleGenerativeAI(
            model="gemini-2.5-flash",
            temperature=0,
            timeout=15,
            max_retries=2,
        )
    return _llm_singleton

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
# Custom Tools (bound to the LLM so the agents genuinely decide to invoke
# them, instead of Python code calling them imperatively and parsing prose)
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

@tool
def lookup_asset_tool(ip_address: str) -> str:
    """Look up the hostname, criticality, and network zone of an internal asset by IP address."""
    return lookup_asset(ip_address)

blocked_ips = set()
blocked_ips_lock = threading.Lock()

# Metadata (blocked_at / expires_at) per blocked IP, so containment isn't
# permanent-until-full-reset - it expires and gets reviewed instead.
block_metadata = {}
BLOCK_TTL_SECONDS = int(os.getenv("BLOCK_TTL_SECONDS", str(60 * 60)))  # 1 hour default

# Infrastructure the agent must never sever, regardless of what an alert or an
# LLM decides - the sensor's own gateway addresses and every registered internal
# asset by default (a flow captured independently on eth0 vs eth1 can come back
# with source/destination reversed, which has been observed to make the agent
# try to block a registered asset instead of the real attacker), extensible via env.
DEFAULT_PROTECTED_IPS = {"10.5.1.254", "10.5.2.254"} | set(asset_db.keys())
PROTECTED_IPS = DEFAULT_PROTECTED_IPS | {ip.strip() for ip in os.getenv("PROTECTED_IPS", "").split(",") if ip.strip()}

# Cap on blocks per rolling window, so a false-positive storm (or a spoofed,
# randomized-source volumetric attack) can't autonomously blackhole large
# swaths of the network before a human notices. Tune via env for demos where
# you want to show many legitimate blocks succeeding in a short window.
MAX_BLOCKS_PER_WINDOW = int(os.getenv("MAX_BLOCKS_PER_WINDOW", "20"))
BLOCK_RATE_WINDOW_SECONDS = 60
block_timestamps = []
rate_limit_lock = threading.Lock()

def block_ip(source_ip: str, action_label: str = "Automated LangGraph Block") -> str:
    if source_ip in PROTECTED_IPS:
        msg = f"REFUSED: {source_ip} is on the protected allow-list and cannot be blocked by the agent."
        logger.warning(msg)
        store.add_mitigation({"target_ip": source_ip, "action": action_label, "status": "REFUSED", "message": msg})
        return msg

    with blocked_ips_lock:
        if source_ip in blocked_ips:
            msg = f"INFO: IP {source_ip} is already blocked."
            store.add_mitigation({"target_ip": source_ip, "action": action_label, "status": "INFO", "message": msg})
            return msg

    with rate_limit_lock:
        now = time.time()
        while block_timestamps and now - block_timestamps[0] > BLOCK_RATE_WINDOW_SECONDS:
            block_timestamps.pop(0)
        if len(block_timestamps) >= MAX_BLOCKS_PER_WINDOW:
            msg = f"RATE LIMITED: {MAX_BLOCKS_PER_WINDOW} blocks already deployed in the last {BLOCK_RATE_WINDOW_SECONDS}s. Skipping auto-containment for {source_ip} - escalate for manual review."
            logger.warning(msg)
            store.add_mitigation({"target_ip": source_ip, "action": action_label, "status": "RATE_LIMITED", "message": msg})
            return msg
        block_timestamps.append(now)

    try:
        # Check if the IP is already blocked at the iptables layer
        check_cmd = ["iptables", "-C", "FORWARD", "-s", source_ip, "-j", "DROP"]
        if subprocess.run(check_cmd, capture_output=True).returncode == 0:
            with blocked_ips_lock:
                blocked_ips.add(source_ip)
                block_metadata[source_ip] = {"blocked_at": time.time(), "expires_at": time.time() + BLOCK_TTL_SECONDS}
            msg = f"INFO: IP {source_ip} is already blocked."
            store.add_mitigation({"target_ip": source_ip, "action": action_label, "status": "INFO", "message": msg})
            return msg

        # Appends a DROP rule
        command = ["iptables", "-A", "FORWARD", "-s", source_ip, "-j", "DROP"]
        subprocess.run(command, check=True, capture_output=True, text=True)
        with blocked_ips_lock:
            blocked_ips.add(source_ip)
            block_metadata[source_ip] = {"blocked_at": time.time(), "expires_at": time.time() + BLOCK_TTL_SECONDS}
        msg = f"SUCCESS: Iptables rule deployed. IP {source_ip} is now blocked at the routing layer (expires in {BLOCK_TTL_SECONDS}s unless renewed)."
        store.add_mitigation({"target_ip": source_ip, "action": action_label, "status": "SUCCESS", "message": msg})
        return msg
    except Exception as e:
        err = f"FAILED: System error during iptables execution: {str(e)}"
        store.add_mitigation({"target_ip": source_ip, "action": action_label, "status": "FAILED", "message": err})
        return err

def unblock_ip(source_ip: str, reason: str = "Manual") -> str:
    try:
        command = ["iptables", "-D", "FORWARD", "-s", source_ip, "-j", "DROP"]
        subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError:
        pass  # rule may already be absent - treat as a no-op success
    with blocked_ips_lock:
        blocked_ips.discard(source_ip)
        block_metadata.pop(source_ip, None)
    msg = f"UNBLOCKED: IP {source_ip} removed from containment ({reason})."
    logger.info(msg)
    store.add_mitigation({"target_ip": source_ip, "action": reason, "status": "SUCCESS", "message": msg})
    return msg

def _sweep_expired_blocks():
    now = time.time()
    with blocked_ips_lock:
        expired = [ip for ip, meta in block_metadata.items() if now >= meta["expires_at"]]
    for ip in expired:
        unblock_ip(ip, reason="TTL Expiry")

def _expiry_sweeper_loop():
    while True:
        time.sleep(30)
        _sweep_expired_blocks()

threading.Thread(target=_expiry_sweeper_loop, daemon=True).start()

# ---------------------------------------------------------
# Tiered autonomy: a false-positive block against a high-value asset costs
# more than one against a low-value asset, so containment against Critical/High
# targets is queued for human sign-off instead of executing immediately.
# ---------------------------------------------------------
APPROVAL_REQUIRED_CRITICALITIES = {"Critical", "High"}
pending_approvals = {}
pending_approvals_lock = threading.Lock()

def request_approval(alert_data: dict, triage_report: Optional[str], context_report: Optional[str]) -> str:
    source_ip = alert_data.get('source_ip')
    target_ip = alert_data.get('destination_ip')
    target_criticality = asset_db.get(target_ip, {}).get('criticality', 'Unknown')
    with pending_approvals_lock:
        pending_approvals[source_ip] = {
            "alert_data": alert_data,
            "triage_report": triage_report,
            "context_report": context_report,
            "target_criticality": target_criticality,
            "created_at": time.time(),
        }
    msg = f"Containment for {source_ip} requires manual approval (target {target_ip} is {target_criticality} criticality)."
    logger.info(msg)
    store.add_flow_event({"step": "Response", "status": "Pending Approval", "message": msg})
    store.add_mitigation({"target_ip": source_ip, "action": "Automated LangGraph Block", "status": "PENDING_APPROVAL", "message": msg})
    return msg

def approve_pending(source_ip: str) -> str:
    with pending_approvals_lock:
        entry = pending_approvals.pop(source_ip, None)
    if not entry:
        return f"No pending approval found for {source_ip}."
    result = block_ip(source_ip, action_label="Approved LangGraph Block")
    store.add_flow_event({"step": "Response", "status": "Approved", "message": f"Manual approval granted for {source_ip}. {result}"})
    return result

def deny_pending(source_ip: str) -> str:
    with pending_approvals_lock:
        entry = pending_approvals.pop(source_ip, None)
    if not entry:
        return f"No pending approval found for {source_ip}."
    msg = f"Manual review denied containment for {source_ip}."
    logger.info(msg)
    store.add_mitigation({"target_ip": source_ip, "action": "Manual Denial", "status": "DENIED", "message": msg})
    store.add_flow_event({"step": "Response", "status": "Denied", "message": msg})
    return msg

def get_pending_approvals() -> dict:
    with pending_approvals_lock:
        return {ip: dict(meta) for ip, meta in pending_approvals.items()}

def get_active_blocks() -> dict:
    with blocked_ips_lock:
        return {ip: dict(meta) for ip, meta in block_metadata.items()}

def reset_mitigation_state():
    with blocked_ips_lock:
        blocked_ips.clear()
        block_metadata.clear()
    with rate_limit_lock:
        block_timestamps.clear()
    with pending_approvals_lock:
        pending_approvals.clear()

def _decide_and_contain(source_ip: str, alert_data: dict, triage_report: Optional[str], context_report: Optional[str]) -> str:
    target_criticality = asset_db.get(alert_data.get('destination_ip'), {}).get('criticality', 'Unknown')
    if target_criticality in APPROVAL_REQUIRED_CRITICALITIES:
        return request_approval(alert_data, triage_report, context_report)
    return block_ip(source_ip)

def make_block_ip_tool(alert_data: dict, triage_report: Optional[str], context_report: Optional[str]):
    """Builds a block_ip_tool bound to this alert's context via closure. LangGraph's
    ToolNode may execute tool calls on a different thread than the caller, so a
    closure is used here instead of thread-local storage, which would silently
    lose the context and skip the criticality gate below."""
    @tool
    def block_ip_tool(source_ip: str) -> str:
        """Deploy an iptables DROP rule to actively contain the given source IP address.
        Only call this if containment is genuinely warranted based on the triage and context reports -
        do not call it if the traffic should be ignored or merely monitored."""
        return _decide_and_contain(source_ip, alert_data, triage_report, context_report)
    return block_ip_tool

def _extract_text(content) -> str:
    """LangChain's message.content is normally a plain string, but some Gemini
    response shapes (e.g. when grounding/citation metadata is attached) come back
    as a list of content blocks like [{'type': 'text', 'text': '...', 'extras': {...}}]
    instead. Every consumer downstream (event_store, the dashboard's markdown
    renderer) expects a flat string - passing the raw list/dict through crashes
    the frontend's React tree with no recovery, since it isn't valid JSX children."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                parts.append(str(block.get('text', block)))
            else:
                parts.append(str(block))
        return "\n".join(parts)
    return str(content)

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
            triage_content = _extract_text(response.content)
        except Exception as e:
            logger.error(f"LLM Error in Triage: {e}")
            triage_content = f"**[LLM ERROR] Triage Report:**\nFallback triggered. Flow matches {attack_type} attack."

    store.add_flow_event({"step": "Triage", "status": "Complete", "message": triage_content})
    return {"triage_report": triage_content}

def context_node(state: AgentState):
    store.add_flow_event({"step": "Context", "status": "In Progress", "message": "Querying asset registry..."})

    target_ip = state["alert_data"]["destination_ip"]

    if LLM_DRY_RUN:
        context = lookup_asset(target_ip)
        context_content = f"**[DRY RUN] Context Report:**\nTarget IP: {target_ip}\nRegistry Data: {context}\n- **Assessment:** Business impact depends on the asset's registered criticality above; see the Response stage for the containment decision."
    else:
        # Let the agent decide to call the registry lookup tool itself, rather
        # than Python fetching it beforehand - and keep the prompt neutral so
        # it doesn't presuppose containment is the right outcome.
        agent = create_react_agent(get_llm(), tools=[lookup_asset_tool])
        prompt = (
            f"A potential attack is targeting IP {target_ip}. Use lookup_asset_tool to check the asset registry, "
            f"then provide a short markdown context report assessing business impact based on what you find. "
            f"Do not conclude whether to contain the traffic - that decision is made in a later step."
        )
        try:
            result = agent.invoke({"messages": [HumanMessage(content=prompt)]})
            context_content = _extract_text(result["messages"][-1].content)
        except Exception as e:
            logger.error(f"LLM Error in Context: {e}")
            context_content = f"**[LLM ERROR] Context Report:**\nFallback triggered. Recommend manual review of target {target_ip}."

    store.add_flow_event({"step": "Context", "status": "Complete", "message": context_content})
    return {"context_report": context_content}

def response_node(state: AgentState):
    store.add_flow_event({"step": "Response", "status": "In Progress", "message": "Evaluating mitigation..."})

    alert = state['alert_data']
    source_ip = alert['source_ip']
    target_criticality = asset_db.get(alert.get('destination_ip'), {}).get('criticality', 'Unknown')
    requires_approval = target_criticality in APPROVAL_REQUIRED_CRITICALITIES

    if LLM_DRY_RUN:
        if requires_approval:
            result = request_approval(alert, state.get('triage_report'), state.get('context_report'))
        else:
            store.add_flow_event({"step": "Response", "status": "Executing", "message": "Threat confirmed. Deploying iptables DROP rule."})
            result = block_ip(source_ip)
    else:
        # Bind block_ip as a real tool and act on whether the model actually
        # invoked it - a structured tool_call, not a substring match on prose,
        # decides whether containment happens. The tool is built per-call via
        # make_block_ip_tool() so it closes over this alert's context (the
        # model itself only supplies a bare source_ip argument), and applies
        # the allow-list/rate-limit/approval gates through _decide_and_contain.
        agent = create_react_agent(get_llm(), tools=[make_block_ip_tool(alert, state.get('triage_report'), state.get('context_report'))])
        prompt = (
            f"Triage report:\n{state['triage_report']}\n\n"
            f"Context report:\n{state['context_report']}\n\n"
            f"Decide whether to contain source IP {source_ip}. If containment is warranted, call block_ip_tool "
            f"with source_ip='{source_ip}'. If not warranted, do not call any tool, and explain why in one sentence."
        )
        try:
            agent_result = agent.invoke({"messages": [HumanMessage(content=prompt)]})
            messages = agent_result["messages"]
            tool_result = next(
                (m.content for m in messages if isinstance(m, ToolMessage) and m.name == "block_ip_tool"),
                None,
            )
            if tool_result is not None:
                if not requires_approval:
                    store.add_flow_event({"step": "Response", "status": "Executing", "message": "Model invoked block_ip_tool. Deploying iptables DROP rule."})
                result = _extract_text(tool_result)
            else:
                result = _extract_text(messages[-1].content)
                store.add_flow_event({"step": "Response", "status": "Bypassed", "message": result})
        except Exception as e:
            logger.error(f"LLM Error in Response: {e}")
            if requires_approval:
                result = request_approval(alert, state.get('triage_report'), state.get('context_report'))
            else:
                store.add_flow_event({"step": "Response", "status": "Executing", "message": "LLM error - failing safe. Deploying iptables DROP rule."})
                result = block_ip(source_ip)

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

# Per-source cooldown so an unrelated attacker isn't invisible just because a
# different source IP tripped the cooldown first.
last_execution_times = {}
cooldown_lock = threading.Lock()
COOLDOWN_PERIOD = 30 # seconds

def trigger_swarm(alert_data: dict):
    source_ip = alert_data.get('source_ip')

    with blocked_ips_lock:
        already_blocked = source_ip in blocked_ips
    if already_blocked:
        logger.info(f"Skipping LangGraph execution. Source IP {source_ip} is already blocked.")
        store.add_flow_event({"step": "Rate Limit", "status": "Bypassed", "message": f"LLM execution skipped. Source IP {source_ip} was already permanently mitigated."})
        return

    with cooldown_lock:
        current_time = time.time()
        last_time = last_execution_times.get(source_ip, 0)
        if current_time - last_time < COOLDOWN_PERIOD:
            logger.info(f"Skipping LangGraph execution. Cooldown active for {COOLDOWN_PERIOD - (current_time - last_time):.1f}s for source {source_ip}.")
            store.add_flow_event({"step": "Rate Limit", "status": "Bypassed", "message": f"LLM API call skipped due to active {COOLDOWN_PERIOD}s cooldown for {source_ip}."})
            return
        last_execution_times[source_ip] = current_time

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
