import { useState, useEffect, useRef } from 'react';
import { Activity, ShieldAlert, Zap, ServerCrash, CheckCircle2, Search, Crosshair, Terminal, FileText, LayoutDashboard, Shield, AlertTriangle, ShieldCheck, Cpu, Clock, Ban, ClipboardCheck } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import ReactMarkdown from 'react-markdown';
import ErrorBoundary from './ErrorBoundary';
import './index.css';

interface Alert {
  timestamp: string;
  source_ip: string;
  source_port: number;
  destination_ip: string;
  destination_port: number;
  protocol: number;
  confidence: number;
  attack_type?: string;
  duration_ms: number;
  total_bytes: number;
}

interface Mitigation {
  timestamp: string;
  target_ip: string;
  action: string;
  status: string;
  message: string;
}

interface FlowEvent {
  timestamp: string;
  step: string;
  status: string;
  message: string;
}

interface PendingApproval {
  alert_data: Alert;
  triage_report: string | null;
  context_report: string | null;
  target_criticality: string;
  created_at: number;
}

interface ActiveBlock {
  blocked_at: number;
  expires_at: number;
}

const formatAge = (epochSeconds: number) => {
  const diff = Date.now() / 1000 - epochSeconds;
  if (diff < 5) return 'just now';
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
};

const formatCountdown = (epochSeconds: number) => {
  const diff = epochSeconds - Date.now() / 1000;
  if (diff <= 0) return 'expiring...';
  if (diff < 60) return `${Math.floor(diff)}s left`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m left`;
  return `${Math.floor(diff / 3600)}h ${Math.floor((diff % 3600) / 60)}m left`;
};

const statusBadgeClass = (status: string) => {
  if (status === 'SUCCESS') return 'safe';
  if (status === 'PENDING_APPROVAL') return 'warning';
  if (['DENIED', 'REFUSED', 'FAILED', 'RATE_LIMITED'].includes(status)) return 'danger';
  return 'info';
};

function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [mitigations, setMitigations] = useState<Mitigation[]>([]);
  const [flowEvents, setFlowEvents] = useState<FlowEvent[]>([]);
  const [pendingApprovals, setPendingApprovals] = useState<Record<string, PendingApproval>>({});
  const [activeBlocks, setActiveBlocks] = useState<Record<string, ActiveBlock>>({});
  const [attackStatus, setAttackStatus] = useState('');
  const [actionStatus, setActionStatus] = useState('');
  const [activeTab, setActiveTab] = useState('dashboard');
  const [systemLogs, setSystemLogs] = useState<string[]>([]);
  const [attackerLogs, setAttackerLogs] = useState<string[]>([]);
  const [logFilter, setLogFilter] = useState('All');
  const [activeAttacks, setActiveAttacks] = useState<Record<string, boolean>>({});
  const [attackerIP, setAttackerIP] = useState('10.5.1.10');
  const [randomizeIP, setRandomizeIP] = useState(false);
  const [useRealTools, setUseRealTools] = useState(false);
  const [manualBlockIp, setManualBlockIp] = useState('');
  const consoleRef = useRef<HTMLDivElement>(null);

  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [alertsRes, mitRes, flowRes, pendingRes, blocksRes] = await Promise.all([
          fetch(`${API_URL}/api/alerts`),
          fetch(`${API_URL}/api/mitigations`),
          fetch(`${API_URL}/api/flow`),
          fetch(`${API_URL}/api/pending_approvals`),
          fetch(`${API_URL}/api/active_blocks`)
        ]);
        if (alertsRes.ok) setAlerts(await alertsRes.json());
        if (mitRes.ok) setMitigations(await mitRes.json());
        if (flowRes.ok) setFlowEvents(await flowRes.json());
        if (pendingRes.ok) setPendingApprovals(await pendingRes.json());
        if (blocksRes.ok) setActiveBlocks(await blocksRes.json());

        if (activeTab === 'logs') {
          const [logsRes, attackerLogsRes] = await Promise.all([
            fetch(`${API_URL}/api/logs`),
            fetch(`${API_URL}/api/attacker_logs`).catch(() => null)
          ]);
          if (logsRes.ok) {
            const data = await logsRes.json();
            setSystemLogs(data.logs);
          }
          if (attackerLogsRes && attackerLogsRes.ok) {
            const data = await attackerLogsRes.json();
            setAttackerLogs(data.logs);
          }
        }
      } catch (err) {
        console.error("Failed to fetch dashboard data:", err);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 1500);
    return () => clearInterval(interval);
  }, [API_URL, activeTab]);

  useEffect(() => {
    if (activeTab === 'logs' && consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
    }
  }, [systemLogs, attackerLogs, logFilter, activeTab]);

  const handleStartAttack = async (type: string) => {
    setAttackStatus('Launching attack...');
    try {
      const res = await fetch(`${API_URL}/api/simulate_attack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, target: '10.5.2.30', source_ip: attackerIP, randomize_ip: randomizeIP, real_tools: useRealTools })
      });
      const data = await res.json();
      if (res.ok) {
          setAttackStatus(data.status);
          setActiveAttacks(prev => ({ ...prev, [type]: true }));
      } else setAttackStatus(`Failed: ${data.error}`);
      setTimeout(() => setAttackStatus(''), 5000);
    } catch (err) {
      setAttackStatus('Network error triggering attack.');
    }
  };

  const handleStopAttack = async (type: string) => {
    setAttackStatus('Stopping attack...');
    try {
      const res = await fetch(`${API_URL}/api/stop_attack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type })
      });
      const data = await res.json();
      if (res.ok) {
          setAttackStatus(data.message);
          setActiveAttacks(prev => ({ ...prev, [type]: false }));
      } else setAttackStatus(`Failed: ${data.error}`);
      setTimeout(() => setAttackStatus(''), 5000);
    } catch (err) {
      setAttackStatus('Network error stopping attack.');
    }
  };

  const handleResetEnvironment = async () => {
    setAttackStatus('Resetting environment...');
    try {
      const res = await fetch(`${API_URL}/api/reset`, { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        setAttackStatus('Environment Reset Successfully.');
        setAlerts([]);
        setMitigations([]);
        setFlowEvents([]);
        setPendingApprovals({});
        setActiveBlocks({});
        setSystemLogs([]);
        setAttackerLogs([]);
        setActiveAttacks({});
      } else {
        setAttackStatus(`Reset Failed: ${data.error}`);
      }
      setTimeout(() => setAttackStatus(''), 5000);
    } catch (err) {
      setAttackStatus('Network error resetting environment.');
    }
  };

  const handleClearLogs = async () => {
    try {
      await fetch(`${API_URL}/api/clear_logs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ category: logFilter })
      });
    } catch (err) {
      console.error("Failed to clear logs:", err);
    }
  };

  const flashAction = (message: string) => {
    setActionStatus(message);
    setTimeout(() => setActionStatus(''), 5000);
  };

  const handleApprove = async (ip: string) => {
    try {
      const res = await fetch(`${API_URL}/api/approve`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip_address: ip })
      });
      const data = await res.json();
      flashAction(data.message || `Approved containment for ${ip}.`);
    } catch (err) {
      flashAction('Network error approving.');
    }
  };

  const handleDeny = async (ip: string) => {
    try {
      const res = await fetch(`${API_URL}/api/deny`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip_address: ip })
      });
      const data = await res.json();
      flashAction(data.message || `Dismissed ${ip}.`);
    } catch (err) {
      flashAction('Network error denying.');
    }
  };

  const handleManualBlock = async () => {
    if (!manualBlockIp) return;
    try {
      const res = await fetch(`${API_URL}/api/trigger`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip_address: manualBlockIp })
      });
      const data = await res.json();
      flashAction(data.message || 'Block requested.');
      setManualBlockIp('');
    } catch (err) {
      flashAction('Network error blocking.');
    }
  };

  const handleUnblock = async (ip: string) => {
    try {
      const res = await fetch(`${API_URL}/api/unblock`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip_address: ip })
      });
      const data = await res.json();
      flashAction(data.message || `Unblocked ${ip}.`);
    } catch (err) {
      flashAction('Network error unblocking.');
    }
  };

  // Derived metrics
  const isUnderAttack = alerts.length > 0 && (Date.now() - new Date(alerts[alerts.length - 1]?.timestamp).getTime() < 120000);
  const pendingList = Object.entries(pendingApprovals);
  const activeBlockList = Object.entries(activeBlocks);
  const pendingCount = pendingList.length;
  const activeBlockCount = activeBlockList.length;

  const meanTimeToContainment = (() => {
    const contained = mitigations.filter(m => m.status === 'SUCCESS' && m.action.toLowerCase().includes('block'));
    const diffs: number[] = [];
    contained.forEach(m => {
      const matchingAlert = alerts.find(a => a.source_ip === m.target_ip);
      if (matchingAlert) {
        const diff = (new Date(m.timestamp).getTime() - new Date(matchingAlert.timestamp).getTime()) / 1000;
        if (diff >= 0 && diff < 300) diffs.push(diff);
      }
    });
    if (diffs.length === 0) return null;
    return diffs.reduce((a, b) => a + b, 0) / diffs.length;
  })();

  const statusCounts = mitigations.reduce((acc, m) => {
    acc[m.status] = (acc[m.status] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const chartData = alerts.slice(-20).map(a => ({
    time: new Date(a.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' }),
    bytes: a.total_bytes,
    confidence: a.confidence * 100
  }));

  const getStepState = (stepName: string) => {
    const eventsForStep = flowEvents.filter(e => e.step === stepName);
    if (eventsForStep.length === 0) return { active: false, complete: false, msg: '' };
    const latest = eventsForStep[eventsForStep.length - 1];
    if (latest.status === 'Complete' || latest.status === 'Bypassed') {
      return { active: false, complete: true, msg: latest.message };
    }
    return { active: true, complete: false, msg: latest.message };
  };

  const steps = [
    { id: 'Detection', icon: <Search size={20}/> },
    { id: 'Triage', icon: <Activity size={20}/> },
    { id: 'Context', icon: <ServerCrash size={20}/> },
    { id: 'Response', icon: <ShieldAlert size={20}/> }
  ];

  // Only dos (hping3) and port_sweep (nmap) have a validated real-tool path -
  // the rest keep using the synthetic Scapy engine even with the toggle on.
  const ATTACK_TYPES = [
    { id: 'dos', name: 'Volumetric DoS', icon: <Zap size={18}/>, realTool: true },
    { id: 'port_sweep', name: 'Stealth Port Sweep', icon: <Search size={18}/>, realTool: true },
    { id: 'exploits', name: 'Exploits Payload', icon: <Crosshair size={18}/>, realTool: false },
    { id: 'fuzzers', name: 'Fuzzer Attack', icon: <Activity size={18}/>, realTool: false },
    { id: 'backdoors', name: 'Backdoor Beacon', icon: <ServerCrash size={18}/>, realTool: false }
  ];

  const BREAKDOWN_ROWS = [
    { label: 'Contained', status: 'SUCCESS', cls: 'safe' },
    { label: 'Pending review', status: 'PENDING_APPROVAL', cls: 'warning' },
    { label: 'Denied', status: 'DENIED', cls: 'danger' },
    { label: 'Refused (allow-list)', status: 'REFUSED', cls: 'info' },
    { label: 'Rate limited', status: 'RATE_LIMITED', cls: 'danger' },
  ];
  const breakdownMax = Math.max(1, ...BREAKDOWN_ROWS.map(r => statusCounts[r.status] || 0));

  const renderActionStatus = () => (
    actionStatus ? <div className="action-toast">{actionStatus}</div> : null
  );

  const renderCommandCenter = () => (
    <>
      <div className="dashboard-header">
        <h2 className="dashboard-title">Command Center</h2>
      </div>

      <div className="kpi-grid">
        <div className="kpi-card">
          <div className={`kpi-icon ${isUnderAttack ? 'danger' : 'secure'}`}>
            {isUnderAttack ? <AlertTriangle size={24} /> : <ShieldCheck size={24} />}
          </div>
          <div className="kpi-info">
            <h3>Network Status</h3>
            <p>{isUnderAttack ? 'Under Attack' : 'Secure'}</p>
          </div>
        </div>
        <div className="kpi-card">
          <div className={`kpi-icon ${pendingCount > 0 ? 'danger' : 'cyan'}`}>
            <ClipboardCheck size={24} />
          </div>
          <div className="kpi-info">
            <h3>Pending Review</h3>
            <p>{pendingCount}</p>
          </div>
        </div>
        <div className="kpi-card">
          <div className="kpi-icon purple">
            <Ban size={24} />
          </div>
          <div className="kpi-info">
            <h3>Active Blocks</h3>
            <p>{activeBlockCount}</p>
          </div>
        </div>
        <div className="kpi-card">
          <div className="kpi-icon cyan">
            <Clock size={24} />
          </div>
          <div className="kpi-info">
            <h3>Mean Time to Containment</h3>
            <p>{meanTimeToContainment !== null ? `${meanTimeToContainment.toFixed(1)}s` : 'N/A'}</p>
          </div>
        </div>
      </div>

      <div className="dashboard-grid">
        {/* Left Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div className="glass-panel">
            <div className="panel-title"><Activity size={20} className="text-cyan"/> LangGraph AI Pipeline</div>
            <div className="pipeline-track">
              <div className="pipeline-line"></div>
              {steps.map((step) => {
                const state = getStepState(step.id);
                let cls = "pipeline-node";
                if (state.complete) cls += " complete";
                else if (state.active) cls += " active";

                return (
                  <div key={step.id} className={cls}>
                    <div className="node-circle">{state.complete ? <CheckCircle2 size={20}/> : step.icon}</div>
                    <div className="node-label">{step.id}</div>
                    <div className="node-msg">{state.msg || 'Awaiting'}</div>
                    {state.msg && <div className="tooltip-text"><ReactMarkdown>{state.msg}</ReactMarkdown></div>}
                  </div>
                );
              })}
            </div>
            <div style={{marginTop: '3.5rem'}}></div>
          </div>

          <div className="glass-panel" style={{ flex: 1 }}>
            <div className="panel-title"><Shield size={20} className="text-purple"/> Live Threat Intelligence</div>
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Source</th>
                    <th>Type</th>
                    <th>Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.length === 0 ? (
                    <tr><td colSpan={4} style={{textAlign: 'center', opacity: 0.5}}>No threats detected.</td></tr>
                  ) : (
                    [...alerts].reverse().slice(0, 8).map((alert, i) => (
                      <tr key={i}>
                        <td>{new Date(alert.timestamp).toLocaleTimeString()}</td>
                        <td><span className="badge danger">{alert.source_ip}</span></td>
                        <td>{alert.attack_type || 'Anomaly'}</td>
                        <td className="text-cyan">{(alert.confidence * 100).toFixed(1)}%</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div className="glass-panel">
            <div className="panel-title"><Activity size={20} className="text-cyan"/> Network Anomaly Traffic</div>
            <div style={{ width: '100%', height: '180px' }}>
              <ResponsiveContainer>
                <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorBytes" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.8}/>
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="time" stroke="rgba(255,255,255,0.3)" fontSize={12} tickMargin={10} />
                  <YAxis stroke="rgba(255,255,255,0.3)" fontSize={12} />
                  <Tooltip
                    contentStyle={{ backgroundColor: 'rgba(15, 23, 42, 0.9)', borderColor: '#06b6d4', borderRadius: '8px' }}
                    itemStyle={{ color: '#06b6d4' }}
                  />
                  <Area type="monotone" dataKey="bytes" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#colorBytes)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="glass-panel">
            <div className="panel-title"><ShieldAlert size={20} className="text-cyan"/> Guardrail Activity</div>
            <div className="breakdown-list">
              {BREAKDOWN_ROWS.map(row => {
                const count = statusCounts[row.status] || 0;
                const pct = Math.round((count / breakdownMax) * 100);
                return (
                  <div key={row.label} className="breakdown-row">
                    <span className="breakdown-label">{row.label}</span>
                    <div className="breakdown-track"><div className={`breakdown-fill ${row.cls}`} style={{ width: `${pct}%` }}></div></div>
                    <span className="breakdown-count">{count}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </>
  );

  const renderTriageQueue = () => (
    <>
      <div className="dashboard-header">
        <h2 className="dashboard-title">Triage Queue</h2>
      </div>
      {pendingList.length === 0 ? (
        <div className="glass-panel" style={{ textAlign: 'center', padding: '4rem', opacity: 0.6 }}>
          No pending approvals. Containment against Critical or High criticality assets will wait here for review.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {pendingList.map(([ip, item]) => (
            <div key={ip} className="glass-panel triage-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <span className={`badge ${item.target_criticality === 'Critical' ? 'danger' : 'warning'}`}>{item.target_criticality} asset</span>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{formatAge(item.created_at)}</span>
              </div>
              <div style={{ fontSize: '1.1rem', fontWeight: 700, marginBottom: '4px' }}>
                {ip} <span style={{ color: 'var(--text-secondary)', fontWeight: 400 }}>to</span> {item.alert_data?.destination_ip}
              </div>
              <div style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', marginBottom: '12px' }}>
                {item.alert_data?.attack_type || 'Anomaly'} &middot; {((item.alert_data?.confidence || 0) * 100).toFixed(0)}% confidence
              </div>
              {item.triage_report && (
                <div className="triage-snippet"><ReactMarkdown>{item.triage_report}</ReactMarkdown></div>
              )}
              <div style={{ display: 'flex', gap: '8px', marginTop: '12px' }}>
                <button className="btn btn-start" style={{ flex: 1 }} onClick={() => handleApprove(ip)}>Contain</button>
                <button className="btn btn-reset" style={{ flex: 1, marginTop: 0 }} onClick={() => handleDeny(ip)}>Dismiss</button>
              </div>
            </div>
          ))}
        </div>
      )}
      {renderActionStatus()}
    </>
  );

  const renderMitigations = () => (
    <>
      <div className="dashboard-header">
        <h2 className="dashboard-title">Mitigations</h2>
      </div>

      <div className="glass-panel" style={{ marginBottom: '1.5rem' }}>
        <div className="panel-title"><Ban size={20} className="text-cyan"/> Manual Block</div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <div className="input-group" style={{ flex: 1 }}>
            <input type="text" placeholder="10.5.1.x" value={manualBlockIp} onChange={(e) => setManualBlockIp(e.target.value)} />
          </div>
          <button className="btn btn-stop" onClick={handleManualBlock}>Block</button>
        </div>
      </div>

      <div className="glass-panel" style={{ marginBottom: '1.5rem' }}>
        <div className="panel-title"><Shield size={20} className="text-purple"/> Active Blocks ({activeBlockCount})</div>
        {activeBlockList.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '2rem', opacity: 0.5 }}>No active blocks.</div>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead><tr><th>Source IP</th><th>Blocked</th><th>Expires</th><th></th></tr></thead>
              <tbody>
                {activeBlockList.map(([ip, b]) => (
                  <tr key={ip}>
                    <td><span className="badge danger">{ip}</span></td>
                    <td>{formatAge(b.blocked_at)}</td>
                    <td>{formatCountdown(b.expires_at)}</td>
                    <td><button className="btn btn-start" onClick={() => handleUnblock(ip)}>Unblock</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="glass-panel">
        <div className="panel-title"><FileText size={20} className="text-cyan"/> History</div>
        <div className="table-wrapper">
          <table>
            <thead><tr><th>Time</th><th>IP</th><th>Action</th><th>Status</th></tr></thead>
            <tbody>
              {mitigations.length === 0 ? (
                <tr><td colSpan={4} style={{ textAlign: 'center', opacity: 0.5 }}>No mitigation history.</td></tr>
              ) : (
                [...mitigations].map((m, i) => (
                  <tr key={i}>
                    <td>{new Date(m.timestamp).toLocaleTimeString()}</td>
                    <td>{m.target_ip}</td>
                    <td>{m.action}</td>
                    <td><span className={`badge ${statusBadgeClass(m.status)}`}>{m.status}</span></td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
      {renderActionStatus()}
    </>
  );

  const renderSimulation = () => (
    <>
      <div className="dashboard-header">
        <h2 className="dashboard-title">Simulation Control</h2>
      </div>
      <div className="glass-panel" style={{ maxWidth: '640px' }}>
        <div className="panel-title"><Crosshair size={20} className="text-red"/> Attack Simulator</div>

        <div className="attacker-config">
          <div style={{fontSize: '0.85rem', marginBottom: '8px', color: 'var(--text-secondary)'}}>Source IP Configuration</div>
          <div className="input-group">
            <input
              type="text"
              value={attackerIP}
              onChange={(e) => setAttackerIP(e.target.value)}
              disabled={randomizeIP}
              style={{ opacity: randomizeIP ? 0.5 : 1 }}
            />
          </div>
          <label className="checkbox-wrapper">
            <input type="checkbox" checked={randomizeIP} onChange={(e) => setRandomizeIP(e.target.checked)} />
            <span style={{fontSize: '0.85rem', color: 'var(--text-secondary)'}}>Randomize IP (Spoofing)</span>
          </label>
          <label className="checkbox-wrapper">
            <input type="checkbox" checked={useRealTools} onChange={(e) => setUseRealTools(e.target.checked)} />
            <span style={{fontSize: '0.85rem', color: 'var(--text-secondary)'}}>Use Real Attack Tools (nmap / hping3)</span>
          </label>
          {useRealTools && (
            <div style={{fontSize: '0.75rem', color: 'var(--text-secondary)', opacity: 0.7, marginTop: '4px'}}>
              Only DoS and Port Sweep run a real tool - other types still use the synthetic engine.
            </div>
          )}
        </div>

        <div className="attack-list">
          {ATTACK_TYPES.map((attack) => (
            <div key={attack.id} className={`attack-card ${activeAttacks[attack.id] ? 'running' : ''}`}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '0.9rem', fontWeight: 600 }}>
                <span style={{ color: activeAttacks[attack.id] ? 'var(--accent-red)' : 'var(--text-secondary)' }}>{attack.icon}</span>
                {attack.name}
                {useRealTools && attack.realTool && (
                  <span style={{fontSize: '0.65rem', padding: '2px 6px', borderRadius: '4px', background: 'var(--accent-red)', color: '#fff', fontWeight: 700}}>REAL</span>
                )}
              </div>
              {activeAttacks[attack.id] ? (
                <button className="btn btn-stop" onClick={() => handleStopAttack(attack.id)}>Stop</button>
              ) : (
                <button className="btn btn-start" onClick={() => handleStartAttack(attack.id)}>Start</button>
              )}
            </div>
          ))}
        </div>

        <button className="btn btn-reset" onClick={handleResetEnvironment}>Global Reset</button>
        {attackStatus && <div style={{marginTop: '10px', fontSize: '0.85rem', textAlign: 'center', color: attackStatus.includes('Fail') ? 'var(--accent-red)' : 'var(--accent-green)'}}>{attackStatus}</div>}
      </div>
    </>
  );

  const renderReports = () => {
    const aiEvents = flowEvents.filter(e => (e.step === 'Triage' || e.step === 'Context') && e.status === 'Complete');
    return (
      <>
        <div className="dashboard-header">
          <h2 className="dashboard-title">AI Intelligence Reports</h2>
        </div>
        {aiEvents.length === 0 ? (
          <div style={{textAlign: 'center', padding: '4rem', opacity: 0.5}}>No AI analysis generated yet.</div>
        ) : (
          <div className="report-grid">
            {[...aiEvents].reverse().map((ev, i) => (
              <div key={i} className="report-card">
                <div className="report-header">
                  <div className="report-step"><Cpu size={16}/> {ev.step} Analysis</div>
                  <div className="report-time">{new Date(ev.timestamp).toLocaleTimeString()}</div>
                </div>
                <div className="report-body"><ReactMarkdown>{ev.message}</ReactMarkdown></div>
              </div>
            ))}
          </div>
        )}
      </>
    );
  };

  const renderLogs = () => {
    const logCategories = ['All', 'ML Pipeline', 'Orchestrator', 'Sensor', 'API', 'Attacker'];
    let displayLogs = [];
    if (logFilter === 'All') {
      displayLogs = [...systemLogs, ...attackerLogs].sort();
    } else if (logFilter === 'Attacker') {
      displayLogs = attackerLogs;
    } else {
      displayLogs = systemLogs.filter(log => log.includes(`[${logFilter}]`));
    }

    return (
      <>
        <div className="dashboard-header">
          <h2 className="dashboard-title">System Debug Console</h2>
        </div>
        <div className="log-filters" style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem'}}>
          <div style={{display: 'flex', gap: '8px', flexWrap: 'wrap'}}>
            {logCategories.map(cat => (
              <button key={cat} className={`filter-btn ${logFilter === cat ? 'active' : ''}`} onClick={() => setLogFilter(cat)}>{cat}</button>
            ))}
          </div>
          <button className="btn btn-stop" style={{padding: '6px 12px', fontSize: '0.8rem', whiteSpace: 'nowrap'}} onClick={handleClearLogs}>Clear {logFilter} Logs</button>
        </div>
        <div className="debug-console" ref={consoleRef}>
          {displayLogs.length === 0 ? (
            <div style={{opacity: 0.5}}>Awaiting log streams...</div>
          ) : (
            displayLogs.map((log, i) => <div key={i} className="debug-line">{log}</div>)
          )}
        </div>
      </>
    );
  };

  return (
    <div className="app-container">
      <div className="sidebar">
        <div className="brand">
          <Shield className="brand-icon" size={36} />
          <div>
            <h1>SOC Brain</h1>
            <div style={{fontSize: '0.75rem', color: 'var(--accent-cyan)', textTransform: 'uppercase', letterSpacing: '1px', marginTop: '4px'}}>Autonomous Engine</div>
          </div>
        </div>

        <div className="nav-links">
          <div className={`nav-item ${activeTab === 'dashboard' ? 'active' : ''}`} onClick={() => setActiveTab('dashboard')}>
            <LayoutDashboard size={20} /> Command Center
          </div>
          <div className={`nav-item ${activeTab === 'triage' ? 'active' : ''}`} onClick={() => setActiveTab('triage')}>
            <ClipboardCheck size={20} /> Triage Queue
            {pendingCount > 0 && <span className="nav-badge">{pendingCount}</span>}
          </div>
          <div className={`nav-item ${activeTab === 'mitigations' ? 'active' : ''}`} onClick={() => setActiveTab('mitigations')}>
            <Ban size={20} /> Mitigations
          </div>
          <div className={`nav-item ${activeTab === 'reports' ? 'active' : ''}`} onClick={() => setActiveTab('reports')}>
            <FileText size={20} /> AI Reports
          </div>
          <div className={`nav-item ${activeTab === 'simulation' ? 'active' : ''}`} onClick={() => setActiveTab('simulation')}>
            <Crosshair size={20} /> Simulation Control
          </div>
          <div className={`nav-item ${activeTab === 'logs' ? 'active' : ''}`} onClick={() => setActiveTab('logs')}>
            <Terminal size={20} /> Debug Logs
          </div>
        </div>

        <div className="sidebar-footer">
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div className={`status-dot ${isUnderAttack ? 'danger' : ''}`}></div>
            <span style={{ fontSize: '0.85rem', fontWeight: 600, color: isUnderAttack ? 'var(--accent-red)' : 'var(--accent-cyan)' }}>
              System {isUnderAttack ? 'Under Attack' : 'Secure'}
            </span>
          </div>
        </div>
      </div>

      <div className="main-content">
        <ErrorBoundary key={activeTab}>
          {activeTab === 'dashboard' && renderCommandCenter()}
          {activeTab === 'triage' && renderTriageQueue()}
          {activeTab === 'mitigations' && renderMitigations()}
          {activeTab === 'reports' && renderReports()}
          {activeTab === 'simulation' && renderSimulation()}
          {activeTab === 'logs' && renderLogs()}
        </ErrorBoundary>
      </div>
    </div>
  );
}

export default App;
