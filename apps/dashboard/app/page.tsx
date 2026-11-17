"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Background, Controls, Edge, Node, ReactFlow } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Activity, AlertTriangle, Archive, ArrowUpRight, Check, ChevronRight, CircleHelp, CloudUpload, Fingerprint, KeyRound, LockKeyhole, LogOut, Network, Play, RefreshCw, RotateCw, Search, Shield, ShieldAlert, Siren, TerminalSquare, Timer, Workflow, type LucideIcon } from "lucide-react";
import { API, api, login } from "@/lib/api";

type Risk = { overall_score: number; target_level: string; target_threshold: number; active_threshold: number; recovery_frozen: boolean; node_scores: Record<string, number>; explanations: { event_id: string; kind: string; effective_points: number; age_seconds: number }[] };
type Vault = { id: string; name: string; status: string; active_epoch: null | { id: string; status: string; threshold: number; n: number; encryption_version: number; created_at: string | null } };
type NodeInfo = { node_id: number; status: string; risk_score: number; share_generations: number; invalid_responses: number; signing_key_fingerprint: string };
type Dashboard = { overall_risk: number; target_quorum: number; active_quorum: number; active_epoch_count: number; vault_count: number; pending_recoveries: number; recovery_frozen: boolean; node_scores: Record<string, number>; recent_events: { id: number; type: string; actor: string; created_at: string }[] };
type Audit = { verified: boolean; events: { id: number; type: string; actor: string; payload: Record<string, unknown>; hash: string; created_at: string }[] };
type TraceCase = { id: string; leaked_nodes: number[]; identified_nodes: number[]; proof: string; verified: boolean; mode: string };

const nav = [
  ["Overview", Activity], ["Vaults", Archive], ["Node network", Network], ["Risk engine", ShieldAlert],
  ["Recovery", KeyRound], ["Attack lab", Siren], ["Traceability", Fingerprint], ["Audit", Workflow], ["Configuration", TerminalSquare],
] as const;
const inputClass = "w-full rounded-lg border border-[#29404c] bg-[#08131b] px-3 py-2.5 text-sm text-slate-100 outline-none focus:border-cyan-400";
const buttonClass = "inline-flex items-center justify-center gap-2 rounded-lg border border-cyan-400/30 bg-cyan-400/10 px-3.5 py-2.5 text-sm font-medium text-cyan-100 transition hover:bg-cyan-400/20 disabled:cursor-not-allowed disabled:opacity-40";

export default function Home() {
  const [token, setToken] = useState("");
  const [role, setRole] = useState("");
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [tab, setTab] = useState("Overview");
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [risk, setRisk] = useState<Risk | null>(null);
  const [vaults, setVaults] = useState<Vault[]>([]);
  const [nodes, setNodes] = useState<NodeInfo[]>([]);
  const [audit, setAudit] = useState<Audit | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [vaultName, setVaultName] = useState("");
  const [selectedVault, setSelectedVault] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [attackKind, setAttackKind] = useState("invalid_share");
  const [attackNode, setAttackNode] = useState(1);
  const [takeOffline, setTakeOffline] = useState(false);
  const [traceNodes, setTraceNodes] = useState("1");
  const [traceResult, setTraceResult] = useState<TraceCase | null>(null);
  const [recoveryId, setRecoveryId] = useState("");
  const [recoveredFile, setRecoveredFile] = useState("");

  const refresh = useCallback(async () => {
    if (!token) return;
    const [d, r, v, n, a] = await Promise.all([
      api<Dashboard>("/dashboard", token), api<Risk>("/risk/current", token), api<Vault[]>("/vaults", token),
      api<NodeInfo[]>("/nodes", token), api<Audit>("/audit", token),
    ]);
    setDashboard(d); setRisk(r); setVaults(v); setNodes(n); setAudit(a);
    if (!selectedVault && v[0]) setSelectedVault(v[0].id);
  }, [token, selectedVault]);

  useEffect(() => {
    const saved = window.localStorage.getItem("riskshare-session");
    if (saved) {
      try { const value = JSON.parse(saved); setToken(value.token); setRole(value.role); setUsername(value.username); } catch { window.localStorage.removeItem("riskshare-session"); }
    }
  }, []);

  useEffect(() => { refresh().catch((error) => setMessage(error.message)); }, [refresh]);

  useEffect(() => {
    if (!token) return;
    const socket = new WebSocket(`${API.replace("http", "ws")}/ws/events?token=${encodeURIComponent(token)}`);
    socket.onmessage = () => refresh().catch(() => undefined);
    return () => socket.close();
  }, [token, refresh]);

  const withBusy = async (action: () => Promise<void>) => {
    setBusy(true); setMessage("");
    try { await action(); await refresh(); }
    catch (error) { setMessage(error instanceof Error ? error.message : "Operation failed"); }
    finally { setBusy(false); }
  };

  async function signIn(event: FormEvent) {
    event.preventDefault();
    await withBusy(async () => {
      const result = await login(username, password);
      setToken(result.access_token); setRole(result.role); setPassword("");
      window.localStorage.setItem("riskshare-session", JSON.stringify({ token: result.access_token, role: result.role, username }));
    });
  }

  function signOut() { setToken(""); setRole(""); window.localStorage.removeItem("riskshare-session"); }

  async function createVault(event: FormEvent) {
    event.preventDefault();
    await withBusy(async () => {
      const created = await api<{ id: string }>("/vaults", token, { method: "POST", body: JSON.stringify({ name: vaultName }) });
      setVaultName(""); setSelectedVault(created.id); setMessage("Vault created. Upload a file to initialize its encrypted epoch.");
    });
  }

  async function initializeVault() {
    if (!file || !selectedVault) return;
    await withBusy(async () => {
      const encoded = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader(); reader.onload = () => resolve(String(reader.result).split(",")[1] ?? ""); reader.onerror = () => reject(new Error("File read failed")); reader.readAsDataURL(file);
      });
      await api(`/vaults/${selectedVault}/initialize`, token, { method: "POST", body: JSON.stringify({ filename: file.name, content_base64: encoded }) });
      setFile(null); setMessage("Encrypted epoch initialized and acknowledged by all five nodes.");
    });
  }

  async function rotate(threshold?: number) {
    if (!selectedVault) return;
    await withBusy(async () => {
      const data = await api<{ threshold: number }>(`/vaults/${selectedVault}/rotate`, token, { method: "POST", body: JSON.stringify({ threshold }) });
      setMessage(`Fresh epoch activated at ${data.threshold}-of-5. File was re-encrypted under a new DEK.`);
    });
  }

  async function requestRecovery() {
    if (!selectedVault) return;
    await withBusy(async () => {
      const data = await api<{ id: string }>("/recovery-requests", token, { method: "POST", body: JSON.stringify({ vault_id: selectedVault }) });
      setRecoveryId(data.id); setRecoveredFile(""); setMessage(`Recovery request ${data.id.slice(0, 8)} is pending. Sign in as a different administrator to approve it.`);
    });
  }

  async function approveRecovery() {
    await withBusy(async () => {
      const data = await api<{ filename: string; content_base64: string }>(`/recovery-requests/${recoveryId}/approve`, token, { method: "POST" });
      const decoded = atob(data.content_base64); const bytes = Uint8Array.from(decoded, (char) => char.charCodeAt(0));
      const url = URL.createObjectURL(new Blob([bytes]));
      const link = document.createElement("a"); link.href = url; link.download = data.filename; link.click(); URL.revokeObjectURL(url);
      setRecoveredFile(data.filename); setMessage("Recovery completed. The decrypted file was downloaded to this device.");
    });
  }

  async function simulateAttack(event: FormEvent) {
    event.preventDefault();
    await withBusy(async () => {
      const result = await api<{ overall_score: number; active_threshold: number; rotated_epochs: string[] }>("/simulator/attacks", token, { method: "POST", body: JSON.stringify({ kind: attackKind, node_id: attackNode, take_node_offline: takeOffline }) });
      setMessage(`Simulation recorded. Risk ${result.overall_score}; active threshold ${result.active_threshold}-of-5; ${result.rotated_epochs.length} vault epoch(s) rotated.`);
    });
  }

  async function runTrace(event: FormEvent) {
    event.preventDefault();
    await withBusy(async () => {
      const result = await api<TraceCase>("/trace-cases", token, { method: "POST", body: JSON.stringify({ vault_id: selectedVault, leaked_node_ids: traceNodes.split(",").map((x) => Number(x.trim())) }) });
      setTraceResult(result);
    });
  }

  const riskSeries = useMemo(() => (risk?.explanations ?? []).map((item, index) => ({ event: `${index + 1}`, points: item.effective_points, name: item.kind })), [risk]);
  const graphNodes: Node[] = nodes.map((node, index) => ({
    id: String(node.node_id), position: { x: (index % 3) * 200, y: Math.floor(index / 3) * 115 },
    data: { label: <div className="min-w-32 text-center"><div className="mb-1 flex items-center justify-center gap-2"><span className={`h-2 w-2 rounded-full ${node.status === "online" ? "bg-emerald-400" : "bg-rose-400"}`} />Node {node.node_id}</div><div className="text-xs text-slate-400">risk {node.risk_score} · {node.status}</div></div> },
    style: { background: "#0d202a", border: `1px solid ${node.status === "online" ? "#246276" : "#773a48"}`, borderRadius: 12, padding: 10, width: 156 },
  }));
  const graphEdges: Edge[] = nodes.slice(1).map((node, index) => ({ id: `e${index}`, source: String(nodes[0]?.node_id ?? 1), target: String(node.node_id), animated: node.status === "online", style: { stroke: "#315968" } }));
  const metricCards: { label: string; value: string | number; hint: string; Icon: LucideIcon }[] = [
    { label: "Overall risk", value: dashboard?.overall_risk ?? "—", hint: risk?.target_level?.toUpperCase() ?? "loading", Icon: AlertTriangle },
    { label: "Active quorum", value: `${dashboard?.active_quorum ?? "—"}-of-5`, hint: `target ${dashboard?.target_quorum ?? "—"}-of-5`, Icon: KeyRound },
    { label: "Active epochs", value: dashboard?.active_epoch_count ?? "—", hint: `${dashboard?.vault_count ?? 0} vaults`, Icon: Archive },
    { label: "Pending recovery", value: dashboard?.pending_recoveries ?? "—", hint: dashboard?.recovery_frozen ? "recovery frozen" : "approval required", Icon: Timer },
  ];

  if (!token) return <main className="soft-grid flex min-h-screen items-center justify-center p-6"><motion.form initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} onSubmit={signIn} className="panel w-full max-w-md p-8 shadow-2xl shadow-black/30"><div className="mb-8 flex items-center gap-3"><div className="rounded-xl border border-cyan-300/30 bg-cyan-300/10 p-3 text-cyan-200"><Shield size={24} /></div><div><p className="text-xs uppercase tracking-[.25em] text-cyan-300">RiskShare</p><h1 className="text-xl font-semibold">Control Room</h1></div></div><p className="mb-6 text-sm text-slate-400">Risk-adaptive threshold key management · local research demonstrator</p><label className="mb-4 block text-xs text-slate-400">Operator<input value={username} onChange={(e) => setUsername(e.target.value)} className={`${inputClass} mt-2`} /></label><label className="mb-5 block text-xs text-slate-400">Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className={`${inputClass} mt-2`} /></label><button className={`${buttonClass} w-full`} disabled={busy}><LockKeyhole size={16} />Sign in</button>{message && <p className="mt-4 text-sm text-rose-300">{message}</p>}<p className="mt-5 text-xs text-slate-500">Local defaults: admin / dev-admin-change-me · operator / dev-operator-change-me</p></motion.form></main>;

  const activeVault = vaults.find((vault) => vault.id === selectedVault);
  return <main className="min-h-screen">
    <aside className="fixed inset-y-0 left-0 z-20 hidden w-64 border-r border-[#1b2c36] bg-[#08131b]/95 p-4 backdrop-blur-xl lg:block"><div className="mb-9 flex items-center gap-3 px-2 pt-2"><div className="rounded-xl border border-cyan-300/20 bg-cyan-300/10 p-2.5 text-cyan-200"><Shield size={20} /></div><div><p className="text-[10px] uppercase tracking-[.26em] text-cyan-300">RiskShare</p><p className="font-semibold">Control Room</p></div></div><p className="mb-2 px-3 text-[10px] uppercase tracking-[.2em] text-slate-600">Security operations</p><nav className="space-y-1">{nav.map(([name, Icon]) => <button key={name} onClick={() => setTab(name)} className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left text-sm transition ${tab === name ? "bg-cyan-300/10 text-cyan-100" : "text-slate-400 hover:bg-white/5 hover:text-slate-200"}`}><Icon size={16} />{name}{tab === name && <ChevronRight className="ml-auto" size={14} />}</button>)}</nav><div className="absolute bottom-4 left-4 right-4 rounded-xl border border-[#20343f] bg-[#0b1821] p-3"><div className="flex items-center justify-between"><span className="text-xs text-slate-400">Session</span><button onClick={signOut} title="Sign out" className="text-slate-500 hover:text-white"><LogOut size={15} /></button></div><p className="mt-1 text-sm">{username} <span className="text-cyan-300">· {role}</span></p><p className="mt-2 flex items-center gap-1.5 text-[10px] text-amber-300"><CircleHelp size={12} />Local demo · one physical host</p></div></aside>
    <div className="lg:pl-64"><header className="sticky top-0 z-10 flex items-center justify-between border-b border-[#1b2c36] bg-[#071017]/90 px-5 py-3 backdrop-blur-xl lg:px-8"><div><p className="text-xs text-slate-500">Security operations / <span className="text-slate-300">{tab}</span></p><h1 className="text-lg font-semibold">{tab}</h1></div><div className="flex items-center gap-3"><span className="hidden items-center gap-2 text-xs text-slate-400 sm:flex"><span className="h-2 w-2 rounded-full bg-emerald-400" />API connected</span><button onClick={() => refresh().catch((e) => setMessage(e.message))} className="rounded-lg border border-[#29404c] p-2 text-slate-400 hover:text-white"><RefreshCw size={16} /></button><button onClick={signOut} className="rounded-lg border border-[#29404c] p-2 text-slate-400 hover:text-white lg:hidden"><LogOut size={16} /></button></div></header>
      <div className="mx-auto max-w-[1500px] space-y-5 p-4 lg:p-8">
        {message && <div className="flex items-start justify-between gap-3 rounded-lg border border-cyan-300/20 bg-cyan-300/5 px-4 py-3 text-sm text-cyan-100"><span>{message}</span><button onClick={() => setMessage("")} className="text-cyan-300">×</button></div>}
        {tab === "Overview" && <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">{metricCards.map(({ label, value, hint, Icon }, index) => <motion.div key={label} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * .05 }} className="panel p-5"><div className="flex items-center justify-between text-slate-400"><span className="text-sm">{label}</span><Icon size={17} /></div><p className="mt-3 text-3xl font-semibold tracking-tight">{value}</p><p className="mt-1 text-xs text-slate-500">{hint}</p></motion.div>)}</div>
          <div className="grid gap-5 xl:grid-cols-[1.5fr_1fr]"><section className="panel p-5"><div className="mb-4 flex items-center justify-between"><div><h2 className="font-semibold">Risk contributions</h2><p className="mt-1 text-xs text-slate-500">Current decayed event weights from the backend</p></div><Activity className="text-cyan-300" size={18} /></div><div className="h-64">{riskSeries.length ? <ResponsiveContainer width="100%" height="100%"><AreaChart data={riskSeries}><defs><linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#63d3e4" stopOpacity={.35} /><stop offset="100%" stopColor="#63d3e4" stopOpacity={0} /></linearGradient></defs><CartesianGrid stroke="#20343f" vertical={false} /><XAxis dataKey="event" stroke="#657b87" tickLine={false} axisLine={false} /><YAxis stroke="#657b87" tickLine={false} axisLine={false} /><Tooltip contentStyle={{ background: "#0d1b24", border: "1px solid #29404c", borderRadius: 8 }} labelFormatter={(label) => `Event ${label}`} /><Area type="monotone" dataKey="points" stroke="#69d8e8" fill="url(#riskFill)" /></AreaChart></ResponsiveContainer> : <div className="flex h-full items-center justify-center text-sm text-slate-600">No risk events have been recorded</div>}</div></section><section className="panel p-5"><div className="mb-4 flex items-center justify-between"><div><h2 className="font-semibold">Server node network</h2><p className="mt-1 text-xs text-slate-500">Five independent share stores · local host demo</p></div><Network className="text-cyan-300" size={18} /></div><div className="h-64 rounded-lg bg-[#08131b]/60"><ReactFlow nodes={graphNodes} edges={graphEdges} fitView proOptions={{ hideAttribution: true }} nodesDraggable={false} nodesConnectable={false}><Background color="#20343f" gap={20} /><Controls /></ReactFlow></div></section></div>
          <section className="panel p-5"><div className="mb-4 flex items-center justify-between"><h2 className="font-semibold">Recent audit events</h2><button className="text-xs text-cyan-300" onClick={() => setTab("Audit")}>Open audit center <ArrowUpRight size={13} className="inline" /></button></div><EventRows events={dashboard?.recent_events ?? []} /></section>
        </>}
        {tab === "Vaults" && <div className="grid gap-5 xl:grid-cols-[.9fr_1.1fr]"><section className="panel p-5"><h2 className="font-semibold">Distributed key vault</h2><p className="mb-4 mt-1 text-sm text-slate-500">Encrypted objects are bound to immutable cryptographic epochs.</p><form onSubmit={createVault} className="mb-5 flex gap-2"><input className={inputClass} placeholder="Vault name" value={vaultName} onChange={(e) => setVaultName(e.target.value)} required /><button className={buttonClass} disabled={busy}><Archive size={15} />Create</button></form><div className="space-y-2">{vaults.map((vault) => <button onClick={() => setSelectedVault(vault.id)} key={vault.id} className={`w-full rounded-lg border p-3 text-left ${selectedVault === vault.id ? "border-cyan-400/40 bg-cyan-400/5" : "border-[#20343f] bg-[#09151d]"}`}><div className="flex justify-between"><span className="text-sm font-medium">{vault.name}</span><span className="text-xs text-slate-500">{vault.status}</span></div><p className="mt-1 text-xs text-slate-500">{vault.active_epoch ? `${vault.active_epoch.threshold}-of-${vault.active_epoch.n} · epoch ${vault.active_epoch.id.slice(0, 8)}` : "Awaiting encrypted file"}</p></button>)}</div></section><section className="panel p-5"><h2 className="font-semibold">{activeVault?.name ?? "Select a vault"}</h2><p className="mb-5 mt-1 text-xs text-slate-500">Secret material is never displayed in the Control Room.</p>{!activeVault?.active_epoch ? <div className="rounded-lg border border-dashed border-[#31505e] p-6 text-center"><CloudUpload className="mx-auto mb-3 text-cyan-300" /><input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="mx-auto block max-w-full text-sm text-slate-400" /><button onClick={initializeVault} disabled={!file || busy || role !== "admin"} className={`${buttonClass} mt-4`}><LockKeyhole size={15} />Encrypt and distribute</button><p className="mt-3 text-xs text-slate-600">All five nodes must acknowledge the initial share generation.</p></div> : <><div className="grid grid-cols-2 gap-3"><Info label="Epoch" value={activeVault.active_epoch.id} /><Info label="Threshold" value={`${activeVault.active_epoch.threshold}-of-${activeVault.active_epoch.n}`} /><Info label="Encryption" value={`AES-256-GCM v${activeVault.active_epoch.encryption_version}`} /><Info label="Status" value={activeVault.active_epoch.status} /></div><div className="mt-5 flex flex-wrap gap-2"><button onClick={() => rotate()} className={buttonClass} disabled={busy || role !== "admin"}><RotateCw size={15} />Rotate key</button><button onClick={requestRecovery} className={buttonClass} disabled={busy}><KeyRound size={15} />Request recovery</button></div><div className="mt-5 rounded-lg border border-[#20343f] bg-[#08131b] p-3"><p className="text-xs text-slate-500">Previous epochs</p>{vaults.find((v) => v.id === selectedVault) && <p className="mt-1 text-sm">Active epoch shown above. Retired generations remain in audit history.</p>}</div></>}</section></div>}
        {tab === "Node network" && <><div className="panel h-[460px] p-3"><ReactFlow nodes={graphNodes} edges={graphEdges} fitView proOptions={{ hideAttribution: true }} nodesDraggable={false} nodesConnectable={false}><Background color="#20343f" gap={20} /><Controls /></ReactFlow></div><div className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">{nodes.map((node) => <div key={node.node_id} className="panel p-4"><div className="flex justify-between"><b>Node {node.node_id}</b><span className={node.status === "online" ? "text-emerald-300" : "text-rose-300"}>{node.status}</span></div><p className="mt-3 text-xs text-slate-500">Risk {node.risk_score} · {node.share_generations} generations</p><p className="mt-1 truncate text-[10px] text-slate-600">Identity {node.signing_key_fingerprint}</p></div>)}</div></>}
        {tab === "Risk engine" && <div className="grid gap-5 xl:grid-cols-2"><section className="panel p-5"><h2 className="font-semibold">Explainable risk score</h2><div className="my-5 flex items-end gap-3"><span className="text-5xl font-semibold">{risk?.overall_score ?? 0}</span><span className="mb-2 text-sm text-slate-500">/ 100 · target {risk?.target_level} risk</span></div><p className="mb-5 text-sm text-slate-400">Current quorum {risk?.active_threshold}-of-5. Target policy {risk?.target_threshold}-of-5.{risk?.recovery_frozen ? " Recovery is frozen pending a safe epoch transition." : ""}</p><div className="space-y-2">{risk?.explanations.map((item) => <div key={item.event_id} className="flex justify-between rounded-lg border border-[#20343f] bg-[#08131b] px-3 py-2 text-sm"><span>{item.kind.replaceAll("_", " ")}</span><span className="text-amber-300">+{item.effective_points}</span></div>)}</div></section><section className="panel p-5"><h2 className="font-semibold">Policy bands</h2><div className="mt-4 space-y-3">{[["0–29", "LOW", "2-of-5", "text-emerald-300"], ["30–59", "MEDIUM", "3-of-5", "text-amber-300"], ["60–100", "HIGH", "4-of-5", "text-rose-300"]].map(([range, level, threshold, color]) => <div key={level} className="flex items-center justify-between rounded-lg border border-[#20343f] bg-[#08131b] p-3"><span className="text-sm text-slate-400">{range}</span><b className={color}>{level}</b><span className="font-mono text-sm">{threshold}</span></div>)}</div><p className="mt-4 text-xs text-slate-500">Escalation creates a fresh DEK, ciphertext, and share epoch. De-escalation requires admin authorization and cooldown.</p></section></div>}
        {tab === "Recovery" && <section className="panel max-w-3xl p-5"><h2 className="font-semibold">Recovery center</h2><p className="mb-5 mt-1 text-sm text-slate-500">A distinct administrator must approve a pending request. Recovered plaintext is downloaded directly.</p><label className="mb-4 block text-xs text-slate-400">Vault<select className={`${inputClass} mt-2`} value={selectedVault} onChange={(e) => setSelectedVault(e.target.value)}>{vaults.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select></label><button onClick={requestRecovery} disabled={busy || !selectedVault} className={buttonClass}><KeyRound size={15} />Initiate recovery</button><div className="my-5 h-px bg-[#20343f]" /><label className="mb-3 block text-xs text-slate-400">Pending request ID<input className={`${inputClass} mt-2`} value={recoveryId} onChange={(e) => setRecoveryId(e.target.value)} placeholder="Request ID from operator session" /></label><button onClick={approveRecovery} disabled={busy || !recoveryId || role !== "admin"} className={buttonClass}><Check size={15} />Approve and recover</button>{recoveredFile && <p className="mt-3 text-sm text-emerald-300">Recovered {recoveredFile}</p>}</section>}
        {tab === "Attack lab" && <div className="grid gap-5 xl:grid-cols-[.9fr_1.1fr]"><section className="panel p-5"><div className="mb-4 flex items-center gap-2"><Siren className="text-rose-300" /><div><h2 className="font-semibold">Attack simulation</h2><p className="text-xs text-slate-500">Scenario events are labeled simulation data</p></div></div><form onSubmit={simulateAttack} className="space-y-4"><label className="block text-xs text-slate-400">Event<select className={`${inputClass} mt-2`} value={attackKind} onChange={(e) => setAttackKind(e.target.value)}>{["failed_authentication", "abnormal_request_burst", "invalid_share", "invalid_node_signature", "missed_heartbeat", "suspicious_recovery", "failed_recovery", "share_integrity_failure"].map((item) => <option key={item} value={item}>{item.replaceAll("_", " ")}</option>)}</select></label><label className="block text-xs text-slate-400">Target node<select className={`${inputClass} mt-2`} value={attackNode} onChange={(e) => setAttackNode(Number(e.target.value))}>{[1,2,3,4,5].map((id) => <option key={id} value={id}>Node {id}</option>)}</select></label><label className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={takeOffline} onChange={(e) => setTakeOffline(e.target.checked)} />Take the selected node offline</label><button className={`${buttonClass} w-full`} disabled={busy || role !== "admin"}><Play size={15} />Run scenario</button></form></section><section className="panel p-5"><h2 className="font-semibold">Observed system response</h2><p className="mt-2 text-sm text-slate-500">Backend risk engine → policy band → fresh cryptographic epoch. If distribution cannot reach all five nodes, the previous epoch stays active and recovery freezes.</p><div className="mt-5 grid grid-cols-2 gap-3"><Info label="Risk" value={String(dashboard?.overall_risk ?? 0)} /><Info label="Active quorum" value={`${dashboard?.active_quorum ?? 2}-of-5`} /><Info label="Target quorum" value={`${dashboard?.target_quorum ?? 2}-of-5`} /><Info label="Recovery state" value={dashboard?.recovery_frozen ? "Frozen" : "Available"} /></div></section></div>}
        {tab === "Traceability" && <div className="grid gap-5 xl:grid-cols-[.8fr_1.2fr]"><section className="panel p-5"><div className="mb-4 flex items-center gap-2"><Fingerprint className="text-cyan-300" /><h2 className="font-semibold">TTSS-II investigation</h2></div><p className="mb-5 text-sm text-slate-500">Simulate leaked shares from fewer than t nodes. Tracing accesses the reconstruction-box interface and returns a verifiable proof.</p><label className="mb-4 block text-xs text-slate-400">Vault<select className={`${inputClass} mt-2`} value={selectedVault} onChange={(e) => setSelectedVault(e.target.value)}>{vaults.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select></label><label className="mb-4 block text-xs text-slate-400">Leaked node IDs<input className={`${inputClass} mt-2`} value={traceNodes} onChange={(e) => setTraceNodes(e.target.value)} placeholder="1,3" /></label><button onClick={runTrace} className={buttonClass} disabled={busy || role !== "admin"}><Search size={15} />Trace and verify</button></section><section className="panel p-5"><h2 className="font-semibold">Investigation result</h2>{traceResult ? <><div className="mt-4 flex items-center gap-2 text-emerald-300"><Check size={18} />Public verification {traceResult.verified ? "passed" : "failed"}</div><p className="mt-3 text-sm">Identified nodes: <b>{traceResult.identified_nodes.join(", ")}</b></p><p className="mt-2 break-all font-mono text-xs text-slate-500">Proof: {traceResult.proof}</p><p className="mt-3 text-xs text-slate-600">Case {traceResult.id} · {traceResult.mode}</p></> : <p className="mt-4 text-sm text-slate-600">No investigation has been run in this session.</p>}</section></div>}
        {tab === "Audit" && <section className="panel p-5"><div className="mb-5 flex items-center justify-between"><div><h2 className="font-semibold">Tamper-evident audit chain</h2><p className="mt-1 text-xs text-slate-500">Persistent event hashes linked to the previous record</p></div><span className={`rounded-full px-3 py-1 text-xs ${audit?.verified ? "bg-emerald-400/10 text-emerald-300" : "bg-rose-400/10 text-rose-300"}`}>{audit?.verified ? "CHAIN VERIFIED" : "CHECK FAILED"}</span></div><div className="space-y-2">{audit?.events.slice().reverse().map((event) => <div key={event.id} className="grid gap-2 rounded-lg border border-[#20343f] bg-[#08131b] p-3 md:grid-cols-[1.5fr_1fr_2fr]"><div><p className="text-sm font-medium">{event.type}</p><p className="text-[10px] text-slate-600">#{event.id} · {event.actor}</p></div><p className="text-xs text-slate-500">{new Date(event.created_at).toLocaleString()}</p><p className="truncate font-mono text-[10px] text-slate-600">{event.hash}</p></div>)}</div></section>}
        {tab === "Configuration" && <section className="panel max-w-3xl p-5"><h2 className="font-semibold">Demonstrator configuration</h2><p className="mb-5 mt-1 text-sm text-slate-500">Runtime configuration from this build. Secrets are intentionally not displayed.</p><div className="space-y-3"><Info label="API" value={API} /><Info label="Storage" value="SQLite control DB + five separate local node DB files" /><Info label="Node transport" value="In-process demonstrator calls; no mTLS process boundary yet" /><Info label="Cryptography" value="ABSS / TTSS-II, AES-256-GCM, Ed25519 node signatures" /><Info label="Production readiness" value="Research prototype only" /></div></section>}
        <footer className="flex flex-wrap items-center justify-between gap-2 border-t border-[#1b2c36] py-4 text-[10px] text-slate-600"><span>RIS KSHARE · RESEARCH DEMONSTRATOR · SECURITY METRICS FROM CONTROL API</span><span>Live event channel {dashboard ? "connected" : "loading"}</span></footer>
      </div>
    </div>
    <div className="fixed bottom-0 left-0 right-0 z-30 flex overflow-x-auto border-t border-[#1b2c36] bg-[#08131b] p-1 lg:hidden">{nav.map(([name, Icon]) => <button key={name} onClick={() => setTab(name)} className={`min-w-16 flex-1 px-2 py-2 text-[9px] ${tab === name ? "text-cyan-200" : "text-slate-500"}`}><Icon className="mx-auto mb-1" size={16} />{name.split(" ")[0]}</button>)}</div>
  </main>;
}

function Info({ label, value }: { label: string; value: string }) { return <div className="rounded-lg border border-[#20343f] bg-[#08131b] p-3"><p className="text-[10px] uppercase tracking-wide text-slate-600">{label}</p><p className="mt-1 truncate text-sm text-slate-200">{value}</p></div>; }
function EventRows({ events }: { events: { id: number; type: string; actor: string; created_at: string }[] }) { return events.length ? <div className="divide-y divide-[#20343f]">{events.slice().reverse().map((event) => <div key={event.id} className="flex items-center justify-between gap-4 py-3"><div className="flex items-center gap-3"><span className="rounded-lg bg-cyan-300/10 p-2 text-cyan-300"><Activity size={14} /></span><div><p className="text-sm">{event.type}</p><p className="text-xs text-slate-600">{event.actor}</p></div></div><span className="text-xs text-slate-500">{new Date(event.created_at).toLocaleTimeString()}</span></div>)}</div> : <div className="py-8 text-center text-sm text-slate-600">No recorded events yet.</div>; }
