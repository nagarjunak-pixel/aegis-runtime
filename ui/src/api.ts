export interface SystemOverview {
  version: string;
  policy_hash: string;
  policy_rule_count: number;
  ledger: {
    valid: boolean;
    events_checked: number;
    merkle_root: string;
    public_key: string;
  };
  pii_vaulted_secrets: number;
  router_cache: { hits: number; misses: number; hit_rate: number };
  erp: {
    inventory: Array<{
      plant: string;
      sku: string;
      total_units: number;
      available_atp: number;
      reserved: number;
    }>;
    cost_centers: Array<{
      cost_center: string;
      allocated_usd: number;
      available_usd: number;
      encumbered_usd: number;
      settled_usd: number;
    }>;
    invariants: { passed: boolean; violations: string[] };
  };
}

export interface ScenarioDescriptor {
  scenario_id: string;
  title: string;
  category: string;
  expected_outcome: string;
  summary: string;
}

export interface WorkflowRunBundle {
  routing: {
    selected_model_id: string;
    provider: string;
    estimated_cost_usd: number;
    cache_hit: boolean;
    pareto_frontier_models: string[];
  };
  saga_result: {
    workflow_id: string;
    workflow_name: string;
    status: string;
    compensated_steps: number;
    total_latency_ms: number;
    failure_reason: string | null;
    steps: Array<{
      step_name: string;
      tool_name: string;
      status: string;
      attempts: number;
      latency_ms: number;
      error_message: string | null;
      policy_verdict: {
        effect: string;
        deciding_rule_id: string | null;
        reason: string;
        evaluation_latency_us: number;
        taint_violation: boolean;
      };
    }>;
  };
  merkle_root: string;
  ledger_event_count: number;
  conservation_passed: boolean;
}

export interface LedgerEntry {
  seq: number;
  timestamp: string;
  tenant_id: string;
  workflow_id: string;
  event_type: string;
  event_hash: string;
  prev_hash: string;
  signature: string;
}

export interface MerkleProofResponse {
  leaf_index: number;
  tree_size: number;
  event_hash_hex: string;
  root_hash_hex: string;
  verified: boolean;
  audit_path: Array<{ sibling_hash_hex: string; is_left_sibling: boolean }>;
}

export interface ChaosReport {
  total_sagas: number;
  committed_sagas: number;
  compensated_sagas: number;
  blocked_sagas: number;
  orphan_mutations: number;
  conservation_invariants_passed: boolean;
  ledger_events_verified: number;
  policy_eval_p50_us: number;
  policy_eval_p99_us: number;
  saga_latency_p50_ms: number;
  saga_latency_p99_ms: number;
  throughput_sagas_per_sec: number;
  merkle_root: string;
}

export interface RedTeamReport {
  total_attacks: number;
  contained_attacks: number;
  containment_rate_pct: number;
  all_contained: boolean;
  results: Array<{
    attack_id: string;
    category: string;
    title: string;
    contained: boolean;
    defense_layer: string;
    evidence: string;
  }>;
}

export async function apiGet<T>(path: string): Promise<T> {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
  return (await res.json()) as T;
}

export async function apiPost<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : "{}",
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
  return (await res.json()) as T;
}
