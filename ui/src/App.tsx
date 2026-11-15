import { useEffect, useState } from "react";
import {
  apiGet,
  apiPost,
  ChaosReport,
  LedgerEntry,
  MerkleProofResponse,
  RedTeamReport,
  ScenarioDescriptor,
  SystemOverview,
  WorkflowRunBundle,
} from "./api";

type TabKey = "sagas" | "ledger" | "counterfactual" | "chaos";

interface CounterfactualReport {
  workflow_id: string;
  candidate_policy_hash: string;
  total_evaluated_steps: number;
  verdict_flips: number;
  newly_blocked_steps: number;
  newly_permitted_steps: number;
  deltas: Array<{
    seq: number;
    step_name: string;
    tool_name: string;
    amount_usd: number;
    original_effect: string;
    candidate_effect: string;
    flipped: boolean;
    candidate_reason: string;
  }>;
}

export function App() {
  const [tab, setTab] = useState<TabKey>("sagas");
  const [overview, setOverview] = useState<SystemOverview | null>(null);
  const [scenarios, setScenarios] = useState<ScenarioDescriptor[]>([]);
  const [lastRun, setLastRun] = useState<WorkflowRunBundle | null>(null);
  const [events, setEvents] = useState<LedgerEntry[]>([]);
  const [proof, setProof] = useState<MerkleProofResponse | null>(null);
  const [policySource, setPolicySource] = useState<string>("");
  const [cfReport, setCfReport] = useState<CounterfactualReport | null>(null);
  const [chaos, setChaos] = useState<ChaosReport | null>(null);
  const [redteam, setRedteam] = useState<RedTeamReport | null>(null);
  const [busy, setBusy] = useState<boolean>(false);
  const [err, setErr] = useState<string | null>(null);

  const refreshState = async () => {
    try {
      const [ov, sc, ev, pol] = await Promise.all([
        apiGet<SystemOverview>("/api/v1/overview"),
        apiGet<ScenarioDescriptor[]>("/api/v1/scenarios"),
        apiGet<LedgerEntry[]>("/api/v1/ledger/events?limit=60"),
        apiGet<{ source: string }>("/api/v1/policy/source"),
      ]);
      setOverview(ov);
      setScenarios(sc);
      setEvents(ev);
      if (!policySource) setPolicySource(pol.source);
    } catch (e) {
      setErr(String(e));
    }
  };

  useEffect(() => {
    void refreshState();
  }, []);

  const executeScenario = async (id: string) => {
    setBusy(true);
    setErr(null);
    try {
      const bundle = await apiPost<WorkflowRunBundle>(`/api/v1/scenarios/${id}/run`);
      setLastRun(bundle);
      await refreshState();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  const inspectProof = async (seq: number) => {
    setErr(null);
    try {
      const p = await apiGet<MerkleProofResponse>(`/api/v1/ledger/proof/${seq}`);
      setProof(p);
    } catch (e) {
      setErr(String(e));
    }
  };

  const runCounterfactual = async () => {
    const wfId = lastRun?.saga_result.workflow_id || events[events.length - 1]?.workflow_id;
    if (!wfId) {
      setErr("Execute at least one enterprise scenario first to record a workflow_id.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const rep = await apiPost<CounterfactualReport>(
        `/api/v1/replay/${wfId}/counterfactual`,
        { candidate_policy_source: policySource }
      );
      setCfReport(rep);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  const runChaosAndRedteam = async () => {
    setBusy(true);
    setErr(null);
    try {
      const [c, r] = await Promise.all([
        apiPost<ChaosReport>("/api/v1/benchmarks/chaos", {
          transactions: 160,
          fault_rate: 0.25,
        }),
        apiPost<RedTeamReport>("/api/v1/benchmarks/redteam"),
      ]);
      setChaos(c);
      setRedteam(r);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  const statusBadge = (status: string) => {
    if (status === "COMMITTED" || status === "SUCCEEDED")
      return <span className="pill pill-ok">{status}</span>;
    if (status === "COMPENSATED")
      return <span className="pill pill-warn">{status}</span>;
    return <span className="pill pill-err">{status}</span>;
  };

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <h1>
            AegisRuntime Control Tower
            <span className="pill pill-ok">v{overview?.version ?? "0.4.0"}</span>
          </h1>
          <p>
            Zero-Trust AST Policy Gatekeeper · Transactional SAP/ERP Saga Engine · RFC-6962
            Merkle &amp; Ed25519 Audit Ledger
          </p>
        </div>
        <div>
          <span className="pill pill-ok">
            {overview?.erp.invariants.passed ? "Conservation Laws: VERIFIED" : "Checking..."}
          </span>
        </div>
      </header>

      {err && (
        <div className="card" style={{ borderColor: "#f43f5e", marginBottom: 16 }}>
          <strong>Error:</strong> {err}
        </div>
      )}

      <section className="kpi-grid">
        <div className="card">
          <div className="kpi-label">Compiled AST Policy Set</div>
          <div className="kpi-value">{overview?.policy_rule_count ?? 10} Rules</div>
          <div className="kpi-sub mono">
            SHA256: {overview?.policy_hash.slice(0, 16) ?? "..."}
          </div>
        </div>
        <div className="card">
          <div className="kpi-label">Signed Ledger Events</div>
          <div className="kpi-value">{overview?.ledger.events_checked ?? 0}</div>
          <div className="kpi-sub mono">
            Merkle: {overview?.ledger.merkle_root.slice(0, 16) ?? "..."}
          </div>
        </div>
        <div className="card">
          <div className="kpi-label">AES-256-GCM PII Vault</div>
          <div className="kpi-value">{overview?.pii_vaulted_secrets ?? 0} Secrets</div>
          <div className="kpi-sub">Tenant-bound HMAC-SHA256 tokens</div>
        </div>
        <div className="card">
          <div className="kpi-label">Double-Entry Cost Centers</div>
          <div className="kpi-value">
            ${overview?.erp.cost_centers[0]?.available_usd.toLocaleString() ?? "5,000,000"}
          </div>
          <div className="kpi-sub">CC-1000 Available Allocation</div>
        </div>
      </section>

      <nav className="tabs">
        <button
          className={`tab-btn ${tab === "sagas" ? "active" : ""}`}
          onClick={() => setTab("sagas")}
        >
          1. Enterprise ERP Saga Studio
        </button>
        <button
          className={`tab-btn ${tab === "ledger" ? "active" : ""}`}
          onClick={() => setTab("ledger")}
        >
          2. Merkle &amp; Ed25519 Audit Ledger
        </button>
        <button
          className={`tab-btn ${tab === "counterfactual" ? "active" : ""}`}
          onClick={() => setTab("counterfactual")}
        >
          3. Time-Travel Counterfactual Simulator
        </button>
        <button
          className={`tab-btn ${tab === "chaos" ? "active" : ""}`}
          onClick={() => setTab("chaos")}
        >
          4. Chaos &amp; Adversarial Red-Team Lab
        </button>
      </nav>

      {tab === "sagas" && (
        <div className="split-2">
          <div className="card">
            <h3 style={{ marginTop: 0 }}>Fortune-500 Reference Workloads</h3>
            {scenarios.map((sc) => (
              <div key={sc.scenario_id} className="scenario-item">
                <div>
                  <div style={{ fontWeight: 600, marginBottom: 4 }}>{sc.title}</div>
                  <div style={{ fontSize: "0.8rem", color: "#8fa3c2" }}>{sc.summary}</div>
                </div>
                <button
                  className="btn"
                  disabled={busy}
                  onClick={() => void executeScenario(sc.scenario_id)}
                >
                  Execute
                </button>
              </div>
            ))}
          </div>

          <div className="card">
            <h3 style={{ marginTop: 0 }}>Live Saga Execution &amp; Compensation Trace</h3>
            {!lastRun ? (
              <p style={{ color: "#8fa3c2" }}>
                Click <strong>Execute</strong> on any scenario on the left to inspect Pareto
                model routing, sub-millisecond AST policy proofs, and reverse-order ERP
                compensations.
              </p>
            ) : (
              <div>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    marginBottom: 12,
                  }}
                >
                  <div>
                    <span className="mono" style={{ fontSize: "0.82rem", color: "#38bdf8" }}>
                      {lastRun.saga_result.workflow_id}
                    </span>
                    <div style={{ fontSize: "0.8rem", color: "#8fa3c2" }}>
                      Model: <strong>{lastRun.routing.selected_model_id}</strong> · Latency:{" "}
                      {lastRun.saga_result.total_latency_ms} ms · Compensated Steps:{" "}
                      {lastRun.saga_result.compensated_steps}
                    </div>
                  </div>
                  {statusBadge(lastRun.saga_result.status)}
                </div>

                {lastRun.saga_result.steps.map((st) => (
                  <div key={st.step_name} className="step-row">
                    <div style={{ display: "flex", justifyContent: "space-between" }}>
                      <strong>
                        {st.step_name} <span className="mono">({st.tool_name})</span>
                      </strong>
                      {statusBadge(st.status)}
                    </div>
                    <div style={{ fontSize: "0.78rem", color: "#8fa3c2", marginTop: 4 }}>
                      Policy Verdict: <strong>{st.policy_verdict.effect}</strong> (
                      {st.policy_verdict.evaluation_latency_us} µs) — {st.policy_verdict.reason}
                    </div>
                    {st.error_message && (
                      <div style={{ fontSize: "0.78rem", color: "#fb7185", marginTop: 4 }}>
                        Fault / Denial: {st.error_message}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            <h4 style={{ marginTop: 20, marginBottom: 8 }}>
              Live SAP S/4HANA Cost-Center &amp; Plant Conservation State
            </h4>
            <table>
              <thead>
                <tr>
                  <th>Cost Center</th>
                  <th>Allocated</th>
                  <th>Available</th>
                  <th>Encumbered PO</th>
                  <th>Settled Wire</th>
                </tr>
              </thead>
              <tbody>
                {overview?.erp.cost_centers.map((cc) => (
                  <tr key={cc.cost_center}>
                    <td className="mono">{cc.cost_center}</td>
                    <td>${cc.allocated_usd.toLocaleString()}</td>
                    <td>${cc.available_usd.toLocaleString()}</td>
                    <td>${cc.encumbered_usd.toLocaleString()}</td>
                    <td>${cc.settled_usd.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === "ledger" && (
        <div className="split-2">
          <div className="card">
            <h3 style={{ marginTop: 0 }}>Append-Only SHA-256 + Ed25519 Event Journal</h3>
            <table>
              <thead>
                <tr>
                  <th>Seq</th>
                  <th>Event Type</th>
                  <th>Workflow</th>
                  <th>Event SHA-256</th>
                  <th>Proof</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev) => (
                  <tr key={ev.seq}>
                    <td className="mono">#{ev.seq}</td>
                    <td>{ev.event_type}</td>
                    <td className="mono">{ev.workflow_id.slice(0, 14)}</td>
                    <td className="mono">{ev.event_hash.slice(0, 14)}...</td>
                    <td>
                      <button className="btn" onClick={() => void inspectProof(ev.seq)}>
                        Prove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="card">
            <h3 style={{ marginTop: 0 }}>RFC-6962 Binary Merkle Inclusion Proof</h3>
            {!proof ? (
              <p style={{ color: "#8fa3c2" }}>
                Select <strong>Prove</strong> on any ledger sequence row to compute and verify
                its O(log N) domain-separated Merkle audit path against the current root.
              </p>
            ) : (
              <div>
                <p>
                  Verification:{" "}
                  <span className="pill pill-ok">
                    {proof.verified ? "MATHEMATICALLY VERIFIED" : "INVALID"}
                  </span>
                </p>
                <div className="mono" style={{ fontSize: "0.78rem", lineHeight: 1.7 }}>
                  <div>Leaf Index: {proof.leaf_index} (Tree Size: {proof.tree_size})</div>
                  <div>Leaf Event Hash: {proof.event_hash_hex}</div>
                  <div>Merkle Root: {proof.root_hash_hex}</div>
                </div>
                <h4>Audit Sibling Path ({proof.audit_path.length} Hops)</h4>
                {proof.audit_path.map((hop, idx) => (
                  <div key={idx} className="step-row mono" style={{ fontSize: "0.75rem" }}>
                    Hop {idx + 1} ({hop.is_left_sibling ? "LEFT" : "RIGHT"} sibling):{" "}
                    {hop.sibling_hash_hex}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {tab === "counterfactual" && (
        <div className="split-2">
          <div className="card">
            <h3 style={{ marginTop: 0 }}>Candidate `.aegis` Policy DSL Editor</h3>
            <p style={{ fontSize: "0.82rem", color: "#8fa3c2" }}>
              Modify rules below (for example, add{" "}
              <code>
                rule &quot;tight-cap&quot; &#123; effect: forbid when: action.amount_usd &gt;
                5000 &#125;
              </code>
              ) and replay historical ledger traffic to measure exact blast radius.
            </p>
            <textarea
              className="mono"
              value={policySource}
              onChange={(e) => setPolicySource(e.target.value)}
            />
            <div style={{ marginTop: 12 }}>
              <button className="btn" disabled={busy} onClick={() => void runCounterfactual()}>
                Simulate Counterfactual Blast Radius
              </button>
            </div>
          </div>

          <div className="card">
            <h3 style={{ marginTop: 0 }}>Counterfactual Verdict Diff Report</h3>
            {!cfReport ? (
              <p style={{ color: "#8fa3c2" }}>
                Run a scenario in Tab 1, edit the policy DSL on the left, and click{" "}
                <strong>Simulate Counterfactual Blast Radius</strong>.
              </p>
            ) : (
              <div>
                <p>
                  Workflow <span className="mono">{cfReport.workflow_id}</span> · Verdict Flips:{" "}
                  <strong>{cfReport.verdict_flips}</strong> (Newly Blocked:{" "}
                  {cfReport.newly_blocked_steps}, Newly Permitted:{" "}
                  {cfReport.newly_permitted_steps})
                </p>
                <table>
                  <thead>
                    <tr>
                      <th>Step</th>
                      <th>Amount</th>
                      <th>Historical</th>
                      <th>Candidate</th>
                      <th>Flipped?</th>
                    </tr>
                  </thead>
                  <tbody>
                    {cfReport.deltas.map((d) => (
                      <tr key={d.seq}>
                        <td>{d.step_name}</td>
                        <td>${d.amount_usd.toLocaleString()}</td>
                        <td>{d.original_effect}</td>
                        <td>{d.candidate_effect}</td>
                        <td>
                          {d.flipped ? (
                            <span className="pill pill-warn">FLIPPED</span>
                          ) : (
                            <span className="pill pill-ok">UNCHANGED</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {tab === "chaos" && (
        <div>
          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <h3 style={{ margin: 0 }}>
                  Live Distributed Chaos &amp; 12-Vector OWASP/SOX/OFAC Red-Team Harness
                </h3>
                <p style={{ margin: "4px 0 0", fontSize: "0.83rem", color: "#8fa3c2" }}>
                  Injects 25% random HTTP 503 / gateway faults across 160 3-step ERP sagas AND
                  executes all 12 adversarial security &amp; insider tampering attacks.
                </p>
              </div>
              <button className="btn" disabled={busy} onClick={() => void runChaosAndRedteam()}>
                {busy ? "Running Suites..." : "Run Chaos + Red-Team Suites"}
              </button>
            </div>
          </div>

          {chaos && (
            <div className="kpi-grid">
              <div className="card">
                <div className="kpi-label">Orphan ERP Mutations</div>
                <div className="kpi-value" style={{ color: "#34d399" }}>
                  {chaos.orphan_mutations}
                </div>
                <div className="kpi-sub">
                  {chaos.committed_sagas} Committed / {chaos.compensated_sagas} Rolled Back
                </div>
              </div>
              <div className="card">
                <div className="kpi-label">AST Policy Latency (p50 / p99)</div>
                <div className="kpi-value">
                  {chaos.policy_eval_p50_us} / {chaos.policy_eval_p99_us} µs
                </div>
                <div className="kpi-sub">Sub-millisecond formal verification</div>
              </div>
              <div className="card">
                <div className="kpi-label">Control Plane Throughput</div>
                <div className="kpi-value">{chaos.throughput_sagas_per_sec} sagas/s</div>
                <div className="kpi-sub">{chaos.ledger_events_verified} signed events verified</div>
              </div>
              <div className="card">
                <div className="kpi-label">Red-Team Containment</div>
                <div className="kpi-value" style={{ color: "#34d399" }}>
                  {redteam?.containment_rate_pct ?? 100}%
                </div>
                <div className="kpi-sub">
                  {redteam?.contained_attacks}/{redteam?.total_attacks} attacks blocked
                </div>
              </div>
            </div>
          )}

          {redteam && (
            <div className="card">
              <h3 style={{ marginTop: 0 }}>12-Vector Adversarial Containment Matrix</h3>
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Category</th>
                    <th>Attack Vector</th>
                    <th>Defense Layer</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {redteam.results.map((r) => (
                    <tr key={r.attack_id}>
                      <td className="mono">{r.attack_id}</td>
                      <td>{r.category}</td>
                      <td>{r.title}</td>
                      <td>{r.defense_layer}</td>
                      <td>
                        <span className={r.contained ? "pill pill-ok" : "pill pill-err"}>
                          {r.contained ? "CONTAINED" : "BREACHED"}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
