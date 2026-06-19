import { useState, useEffect, useRef } from 'react';
import { Activity, ShieldAlert, Zap, ServerCrash, CheckCircle2, Search, Crosshair, Terminal, FileText, LayoutDashboard, Shield, AlertTriangle, ShieldCheck, Cpu } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import ReactMarkdown from 'react-markdown';
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

function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [mitigations, setMitigations] = useState<Mitigation[]>([]);
  const [flowEvents, setFlowEvents] = useState<FlowEvent[]>([]);
  const [attackStatus, setAttackStatus] = useState('');
  const [activeTab, setActiveTab] = useState('dashboard');
  const [systemLogs, setSystemLogs] = useState<string[]>([]);
  const [attackerLogs, setAttackerLogs] = useState<string[]>([]);
  const [logFilter, setLogFilter] = useState('All');
  const [activeAttacks, setActiveAttacks] = useState<Record<string, boolean>>({});
  const [attackerIP, setAttackerIP] = useState('10.5.1.10');
  const [randomizeIP, setRandomizeIP] = useState(false);
  const consoleRef = useRef<HTMLDivElement>(null);

  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [alertsRes, mitRes, flowRes] = await Promise.all([
          fetch(`${API_URL}/api/alerts`),
          fetch(`${API_URL}/api/mitigations`),
          fetch(`${API_URL}/api/flow`)
        ]);
        if (alertsRes.ok) setAlerts(await alertsRes.json());
        if (mitRes.ok) setMitigations(await mitRes.json());
        if (flowRes.ok) setFlowEvents(await flowRes.json());

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
        body: JSON.stringify({ type, target: '10.5.2.30', source_ip: attackerIP, randomize_ip: randomizeIP })
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

  // KPIs
  const isUnderAttack = alerts.length > 0 && (Date.now() - new Date(alerts[alerts.length - 1]?.timestamp).getTime() < 120000);
  const activeMitigationsCount = mitigations.length;
  const avgConfidence = alerts.length > 0 ? (alerts.reduce((acc, a) => acc + a.confidence, 0) / alerts.length * 100).toFixed(1) : '0.0';

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

  const ATTACK_TYPES = [
    { id: 'dos', name: 'Volumetric DoS', icon: <Zap size={18}/> },
    { id: 'port_sweep', name: 'Stealth Port Sweep', icon: <Search size={18}/> },
    { id: 'exploits', name: 'Exploits Payload', icon: <Crosshair size={18}/> },
    { id: 'fuzzers', name: 'Fuzzer Attack', icon: <Activity size={18}/> },
    { id: 'backdoors', name: 'Backdoor Beacon', icon: <ServerCrash size={18}/> }
  ];

  const renderDashboard = () => (
    <>
      <div className="dashboard-header">
        <h2 className="dashboard-title">Dashboard Overview</h2>
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
          <div className="kpi-icon purple">
            <Cpu size={24} />
          </div>
          <div className="kpi-info">
            <h3>AI Confidence Level</h3>
            <p>{avgConfidence}%</p>
          </div>
        </div>
        <div className="kpi-card">
          <div className="kpi-icon cyan">
            <ShieldAlert size={24} />
          </div>
          <div className="kpi-info">
            <h3>Active Mitigations</h3>
            <p>{activeMitigationsCount}</p>
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
            <div style={{ width: '100%', height: '220px' }}>
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
            </div>

            <div className="attack-list">
              {ATTACK_TYPES.map((attack) => (
                <div key={attack.id} className={`attack-card ${activeAttacks[attack.id] ? 'running' : ''}`}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '0.9rem', fontWeight: 600 }}>
                    <span style={{ color: activeAttacks[attack.id] ? 'var(--accent-red)' : 'var(--text-secondary)' }}>{attack.icon}</span>
                    {attack.name}
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
        </div>
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
            <LayoutDashboard size={20} /> Overview
          </div>
          <div className={`nav-item ${activeTab === 'reports' ? 'active' : ''}`} onClick={() => setActiveTab('reports')}>
            <FileText size={20} /> AI Reports
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
        {activeTab === 'dashboard' && renderDashboard()}
        {activeTab === 'reports' && renderReports()}
        {activeTab === 'logs' && renderLogs()}
      </div>
    </div>
  );
}

export default App;
