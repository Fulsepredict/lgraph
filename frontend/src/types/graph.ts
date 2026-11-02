/**
 * Единые контракты данных фронтенда Lgraph, зеркальные ответам FastAPI демона.
 */

export type RiskLevel = 'low' | 'medium' | 'critical';

export interface ProjectRecord {
  project_id: string;
  name: string;
  root_path: string;
  index_revision: number;
  indexed_at_iso: string;
  is_stale: number;
}

export interface IndexReport {
  project_id: string;
  project_name: string;
  index_revision: number;
  elapsed_ms: number;
  parsed_files: number;
  cache_hits: number;
  total_nodes: number;
  total_edges: number;
}

export interface ProjectStats {
  project: ProjectRecord;
  nodes_by_type: Record<string, number>;
  edges_by_type: Record<string, number>;
  total_nodes: number;
  total_edges: number;
  files_with_redacted_secrets: number;
  critical_risk_nodes: number;
}

export interface OversizedFileInfo {
  rel_path: string;
  lines: number;
}

export interface GraphEdgeDto {
  src_uri: string;
  dst_uri: string;
  edge_type: string;
  confidence: number;
  confidence_tier: string;
  source_module: string;
  evidence: string;
  meta: Record<string, unknown>;
}

export interface GraphNodeDto {
  uri: string;
  node_type: string;
  name: string;
  rel_path: string;
  start_line: number;
  end_line: number;
  c4_level: number;
  risk_level: RiskLevel;
  signature: string;
  summary_ru: string;
  pattern_tag: string;
  parent_uri: string;
  confidence: number;
  source_module: string;
  meta: Record<string, unknown>;
  file_count?: number;
  oversized_files?: OversizedFileInfo[];
  inbound_edges?: GraphEdgeDto[];
  outbound_edges?: GraphEdgeDto[];
}

export interface GuardrailRuleDto {
  rule_id: string;
  title: string;
  severity: string;
  scope: string;
  exclude_scope: string;
  predicate_type: string;
  rationale_ru: string;
  remediation_ru: string;
}

export interface GuardrailViolationDto {
  rule_id: string;
  title: string;
  severity: string;
  matched_scope: string;
  target_uri_or_path: string;
  line_number: number;
  evidence: string;
  why_violated_ru: string;
  how_to_fix_ru: string;
}

export interface GuardrailsReportDto {
  rules: GuardrailRuleDto[];
  violations: GuardrailViolationDto[];
  passed: boolean;
}

export interface ImpactReportDto {
  touched_files: string[];
  modified_c3_uris: string[];
  impacted_c3_uris: string[];
  direct_dependents: Array<{ uri: string; name: string; rel_path: string }>;
  indirect_dependents: Array<{ uri: string; name: string; rel_path: string }>;
  cross_language_impacts: Array<{ changed_uri: string; impacted_uri: string; via: string }>;
  signature_changes?: Array<{
    uri: string;
    name: string;
    rel_path: string;
    old_signature: string;
    new_signature: string;
  }>;
  body_only_changes?: Array<{ uri: string; name: string; rel_path: string }>;
  related_tests: Array<{ uri: string; name: string; rel_path: string }>;
  red_zone_touched: boolean;
  red_zone_items: string[];
  guardrail_violations: GuardrailViolationDto[];
  summary_human_ru: string;
}

export interface StartupContextDto {
  selfRootPath: string;
  initialProjectDir: string | null;
}

declare global {
  interface Window {
    lgraphBridge?: {
      apiRequest: <T = unknown>(payload: { path: string; method?: string; body?: unknown }) => Promise<T>;
      pickProjectFolder: () => Promise<string | null>;
      openFileInEditor: (payload: { rootPath: string; relPath: string }) => Promise<{ ok: boolean }>;
      getStartupContext: () => Promise<StartupContextDto>;
      onExternalOpenFolder: (callback: (folderPath: string) => void) => () => void;
    };
  }
}
