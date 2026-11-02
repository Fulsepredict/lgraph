/**
 * Центральное хранилище состояния экрана Lgraph (Zustand).
 *
 * Почему по умолчанию выбран уровень масштаба `c4Level = 3` (Бизнес-модули):
 * Владелец проекта сразу видит чистую карту из 10–20 смысловых блоков без каши
 * из тысяч мелких функций, но при желании может одним кликом спуститься на уровень C4.
 */

import { create } from 'zustand';
import {
  fetchArchitectureMap,
  fetchGuardrailsReport,
  fetchNodePassport,
  fetchOpenedProjects,
  openAndIndexProject,
  runVisualAiDiffImpact,
  saveNodeArchitecturalNote,
  triggerProjectReindex,
} from '../services/api';
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

// Защита от двойного монтирования React 18 <StrictMode> и гонок параллельных переключений проектов
let activeBootPromise: Promise<void> | null = null;
let latestProjectLoadSeq = 0;

interface GraphUiState {
  projects: ProjectRecord[];
  selfRootPath: string | null;
  activeProjectId: string | null;
  activeStats: ProjectStats | null;
  lastIndexReport: IndexReport | null;
  c4Level: number;
  mapNodes: GraphNodeDto[];
  mapEdges: GraphEdgeDto[];
  selectedNode: GraphNodeDto | null;
  guardrailsReport: GuardrailsReportDto | null;
  impactReport: ImpactReportDto | null;
  isDiffRadarActive: boolean;
  isHealthRadarActive: boolean;
  searchQuery: string;
  riskFilter: 'all' | RiskLevel;
  isLoading: boolean;
  errorMessage: string | null;

  bootInitialProjects: () => Promise<void>;
  openProjectByPath: (rootPath: string) => Promise<void>;
  selectExistingProject: (projectId: string) => Promise<void>;
  reindexActiveProject: () => Promise<void>;
  setC4Level: (level: number) => Promise<void>;
  selectNodeByUri: (uri: string | null) => Promise<void>;
  saveNoteForSelectedNode: (summaryRu: string, riskLevel: RiskLevel) => Promise<void>;
  toggleDiffRadar: () => Promise<void>;
  toggleHealthRadar: () => void;
  setSearchQuery: (q: string) => void;
  setRiskFilter: (risk: 'all' | RiskLevel) => void;
  clearError: () => void;
}

export const useGraphStore = create<GraphUiState>((set, get) => ({
  projects: [],
  selfRootPath: null,
  activeProjectId: null,
  activeStats: null,
  lastIndexReport: null,
  c4Level: 3,
  mapNodes: [],
  mapEdges: [],
  selectedNode: null,
  guardrailsReport: null,
  impactReport: null,
  isDiffRadarActive: false,
  isHealthRadarActive: true,
  searchQuery: '',
  riskFilter: 'all',
  isLoading: false,
  errorMessage: null,

  bootInitialProjects: async () => {
    if (activeBootPromise) {
      return activeBootPromise;
    }
    activeBootPromise = (async () => {
      try {
        const startupCtx = await window.lgraphBridge?.getStartupContext().catch(() => null);
        if (startupCtx?.selfRootPath) {
          set({ selfRootPath: startupCtx.selfRootPath });
        }
        if (startupCtx?.initialProjectDir) {
          await get().openProjectByPath(startupCtx.initialProjectDir);
          return;
        }
        const { projects } = await fetchOpenedProjects();
        set({ projects });
        if (projects.length > 0 && !get().activeProjectId && latestProjectLoadSeq === 0) {
          await get().selectExistingProject(projects[0].project_id);
        }
      } catch (err) {
        set({ errorMessage: err instanceof Error ? err.message : String(err) });
      }
    })();
    return activeBootPromise;
  },

  openProjectByPath: async (rootPath: string) => {
    const reqSeq = ++latestProjectLoadSeq;
    set({ isLoading: true, errorMessage: null });
    try {
      const { index_report, stats } = await openAndIndexProject(rootPath);
      const pid = index_report.project_id;
      const [{ projects }, mapData, guardrails] = await Promise.all([
        fetchOpenedProjects(),
        fetchArchitectureMap(pid, get().c4Level),
        fetchGuardrailsReport(pid),
      ]);
      if (reqSeq !== latestProjectLoadSeq) {
        return;
      }
      set({
        projects,
        activeProjectId: pid,
        activeStats: stats,
        lastIndexReport: index_report,
        mapNodes: mapData.nodes,
        mapEdges: mapData.edges,
        guardrailsReport: guardrails,
        selectedNode: null,
        impactReport: null,
        isDiffRadarActive: false,
        isLoading: false,
      });
    } catch (err) {
      if (reqSeq !== latestProjectLoadSeq) {
        return;
      }
      set({
        isLoading: false,
        errorMessage: err instanceof Error ? err.message : String(err),
      });
    }
  },

  selectExistingProject: async (projectId: string) => {
    const reqSeq = ++latestProjectLoadSeq;
    set({ isLoading: true, errorMessage: null });
    try {
      const { index_report, stats } = await triggerProjectReindex(projectId);
      const [mapData, guardrails] = await Promise.all([
        fetchArchitectureMap(projectId, get().c4Level),
        fetchGuardrailsReport(projectId),
      ]);
      if (reqSeq !== latestProjectLoadSeq) {
        return;
      }
      set({
        activeProjectId: projectId,
        activeStats: stats,
        lastIndexReport: index_report,
        mapNodes: mapData.nodes,
        mapEdges: mapData.edges,
        guardrailsReport: guardrails,
        selectedNode: null,
        impactReport: null,
        isDiffRadarActive: false,
        isLoading: false,
      });
    } catch (err) {
      if (reqSeq !== latestProjectLoadSeq) {
        return;
      }
      set({
        isLoading: false,
        errorMessage: err instanceof Error ? err.message : String(err),
      });
    }
  },

  reindexActiveProject: async () => {
    const pid = get().activeProjectId;
    if (!pid) return;
    set({ isLoading: true, errorMessage: null });
    try {
      const { index_report, stats } = await triggerProjectReindex(pid);
      const [mapData, guardrails] = await Promise.all([
        fetchArchitectureMap(pid, get().c4Level),
        fetchGuardrailsReport(pid),
      ]);
      const impact = get().isDiffRadarActive ? await runVisualAiDiffImpact(pid) : null;
      set({
        activeStats: stats,
        lastIndexReport: index_report,
        mapNodes: mapData.nodes,
        mapEdges: mapData.edges,
        guardrailsReport: guardrails,
        impactReport: impact,
        isLoading: false,
      });
    } catch (err) {
      set({
        isLoading: false,
        errorMessage: err instanceof Error ? err.message : String(err),
      });
    }
  },

  setC4Level: async (level: number) => {
    const pid = get().activeProjectId;
    set({ c4Level: level });
    if (!pid) return;
    set({ isLoading: true });
    try {
      const mapData = await fetchArchitectureMap(pid, level);
      set({ mapNodes: mapData.nodes, mapEdges: mapData.edges, isLoading: false });
    } catch (err) {
      set({ isLoading: false, errorMessage: err instanceof Error ? err.message : String(err) });
    }
  },

  selectNodeByUri: async (uri: string | null) => {
    const pid = get().activeProjectId;
    if (!pid || !uri) {
      set({ selectedNode: null });
      return;
    }
    try {
      const { node } = await fetchNodePassport(pid, uri);
      set({ selectedNode: node });
    } catch (err) {
      set({ errorMessage: err instanceof Error ? err.message : String(err) });
    }
  },

  saveNoteForSelectedNode: async (summaryRu: string, riskLevel: RiskLevel) => {
    const { activeProjectId, selectedNode, c4Level } = get();
    if (!activeProjectId || !selectedNode) return;
    try {
      const { node } = await saveNodeArchitecturalNote(activeProjectId, selectedNode.uri, summaryRu, riskLevel);
      const mapData = await fetchArchitectureMap(activeProjectId, c4Level);
      set({ selectedNode: node, mapNodes: mapData.nodes, mapEdges: mapData.edges });
    } catch (err) {
      set({ errorMessage: err instanceof Error ? err.message : String(err) });
    }
  },

  toggleDiffRadar: async () => {
    const { activeProjectId, isDiffRadarActive } = get();
    if (!activeProjectId) return;
    if (isDiffRadarActive) {
      set({ isDiffRadarActive: false, impactReport: null });
      return;
    }
    set({ isLoading: true });
    try {
      const report = await runVisualAiDiffImpact(activeProjectId);
      set({ isDiffRadarActive: true, impactReport: report, isLoading: false });
    } catch (err) {
      set({ isLoading: false, errorMessage: err instanceof Error ? err.message : String(err) });
    }
  },

  toggleHealthRadar: () => set((s) => ({ isHealthRadarActive: !s.isHealthRadarActive })),
  setSearchQuery: (q: string) => set({ searchQuery: q }),
  setRiskFilter: (risk: 'all' | RiskLevel) => set({ riskFilter: risk }),
  clearError: () => set({ errorMessage: null }),
}));
