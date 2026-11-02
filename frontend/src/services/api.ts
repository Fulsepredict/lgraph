/**
 * Единый клиент связи интерфейса с демоном Lgraph (`lgraphFetch`).
 *
 * Почему вызов назван `lgraphFetch` и описан в корневом `lgraph.yaml`:
 * 1. Внутри окна Electron запросы идут через защищённый IPC-мост без раскрытия токена.
 * 2. Собственный сканер `BridgeLinker` распознаёт `lgraphFetch` и строит живую карту
 *    межъязыковых связей самого приложения Lgraph!
 */

import type {
  GraphEdgeDto,
  GraphNodeDto,
  GuardrailsReportDto,
  ImpactReportDto,
  IndexReport,
  ProjectRecord,
  ProjectStats,
  RiskLevel,
} from '../types/graph';

export async function lgraphFetch<T>(
  subPath: string,
  options?: { method?: 'GET' | 'POST'; body?: unknown }
): Promise<T> {
  const fullApiPath = subPath.startsWith('/api/') ? subPath : `/api${subPath.startsWith('/') ? '' : '/'}${subPath}`;
  const method = options?.method ?? 'GET';

  if (window.lgraphBridge?.apiRequest) {
    return window.lgraphBridge.apiRequest<T>({
      path: fullApiPath,
      method,
      body: options?.body,
    });
  }

  throw new Error('Окно должно быть запущено внутри защищённой оболочки Electron (START_APP.bat).');
}

export async function fetchOpenedProjects(): Promise<{ projects: ProjectRecord[] }> {
  return lgraphFetch('/projects');
}

export async function openAndIndexProject(rootPath: string): Promise<{
  index_report: IndexReport;
  stats: ProjectStats;
}> {
  return lgraphFetch('/projects/open', {
    method: 'POST',
    body: { root_path: rootPath, enable_watcher: true },
  });
}

export async function triggerProjectReindex(projectId: string): Promise<{
  index_report: IndexReport;
  stats: ProjectStats;
}> {
  return lgraphFetch(`/projects/${projectId}/reindex`, { method: 'POST' });
}

export async function fetchArchitectureMap(
  projectId: string,
  maxC4Level: number
): Promise<{ nodes: GraphNodeDto[]; edges: GraphEdgeDto[] }> {
  return lgraphFetch(`/projects/${projectId}/map?max_c4_level=${maxC4Level}`);
}

export async function fetchNodePassport(
  projectId: string,
  uri: string
): Promise<{ node: GraphNodeDto; guardrails_count: number }> {
  return lgraphFetch(`/projects/${projectId}/node?uri=${encodeURIComponent(uri)}`);
}

export async function saveNodeArchitecturalNote(
  projectId: string,
  targetUri: string,
  summaryRu: string,
  riskLevel: RiskLevel | ''
): Promise<{ ok: boolean; node: GraphNodeDto }> {
  return lgraphFetch(`/projects/${projectId}/notes`, {
    method: 'POST',
    body: { target_uri: targetUri, summary_ru: summaryRu, risk_level: riskLevel },
  });
}

export async function fetchGuardrailsReport(projectId: string): Promise<GuardrailsReportDto> {
  return lgraphFetch(`/projects/${projectId}/guardrails`);
}

export async function runVisualAiDiffImpact(
  projectId: string,
  targetPaths: string[] = []
): Promise<ImpactReportDto> {
  return lgraphFetch(`/projects/${projectId}/impact`, {
    method: 'POST',
    body: { target_uris_or_paths: targetPaths, git_diff_text: '' },
  });
}

export async function searchProjectNodes(
  projectId: string,
  query: string,
  limit = 20
): Promise<{ results: GraphNodeDto[] }> {
  return lgraphFetch(`/projects/${projectId}/search?q=${encodeURIComponent(query)}&limit=${limit}`);
}

/**
 * Скрывает служебный тег изоляции `<untrusted_code_doc>` только на экране человека.
 * В базе данных и MCP-ответах для нейросети защитная обёртка сохраняется целиком.
 */
export function cleanHumanDocText(raw: string | null | undefined): string {
  if (!raw) return '';
  return raw.replace(/<\/?untrusted_code_doc>/g, '').trim();
}

/**
 * Преобразует относительный путь файла из отчёта нарушений Guardrails в канонический URI узла.
 */
export function resolvePathOrUriToNodeUri(targetPathOrUri: string): string {
  if (targetPathOrUri.includes('://')) return targetPathOrUri;
  const norm = targetPathOrUri.replace(/\\/g, '/').replace(/^\/+/, '');
  if (norm.endsWith('.py') || norm.endsWith('.pyi')) return `py://${norm}`;
  if (norm.endsWith('.ts') || norm.endsWith('.tsx')) return `ts://${norm}`;
  return `js://${norm}`;
}
