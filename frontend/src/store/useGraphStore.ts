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

// Счётчики поколений исключают гонки при быстром переключении проектов и карточек узлов
let activeBootPromise: Promise<void> | null = null;
let latestProjectLoadSeq = 0;
let latestNodeSelectSeq = 0;

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
  saveNoteForSelectedNode: (summaryRu: string, riskLevel: RiskLevel) => Promise<boolean>;
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
    if (activeBootPromise) return activeBootPromise;
    activeBootPromise = (async () => {
      try {
        const startupCtx = await window.lgraphBridge?.getStartupContext().catch(() => null);
        if (startupCtx?.selfRootPath) set({ selfRootPath: startupCtx.selfRootPath });
        if (startupCtx?.initialProjectDir) {
          await get().openProjectByPath(startupCtx.initialProjectDir);
          return;
        }
        const { projects } = await fetchOpenedProjects();
        if (latestProjectLoadSeq === 0) set({ projects });
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
    ++latestNodeSelectSeq;
    set({ isLoading: true, errorMessage: null });
    try {
      const { index_report, stats } = await openAndIndexProject(rootPath);
      if (reqSeq !== latestProjectLoadSeq) return;
      const pid = index_report.project_id;
      const [{ projects }, mapData, guardrails] = await Promise.all([
        fetchOpenedProjects(),
        fetchArchitectureMap(pid, get().c4Level),
        fetchGuardrailsReport(pid),
      ]);
      if (reqSeq !== latestProjectLoadSeq) return;
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
      if (reqSeq !== latestProjectLoadSeq) return;
      set({ isLoading: false, errorMessage: err instanceof Error ? err.message : String(err) });
    }
  },

  selectExistingProject: async (projectId: string) => {
    const reqSeq = ++latestProjectLoadSeq;
    ++latestNodeSelectSeq;
    set({ isLoading: true, errorMessage: null });
    try {
      const { index_report, stats } = await triggerProjectReindex(projectId);
      if (reqSeq !== latestProjectLoadSeq) return;
      const [mapData, guardrails] = await Promise.all([
        fetchArchitectureMap(projectId, get().c4Level),
        fetchGuardrailsReport(projectId),
      ]);
      if (reqSeq !== latestProjectLoadSeq) return;
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
      if (reqSeq !== latestProjectLoadSeq) return;
      set({ isLoading: false, errorMessage: err instanceof Error ? err.message : String(err) });
    }
  },

  reindexActiveProject: async () => {
    const pid = get().activeProjectId;
    if (!pid) return;
    const reqSeq = latestProjectLoadSeq;
    set({ isLoading: true, errorMessage: null });
    try {
      const { index_report, stats } = await triggerProjectReindex(pid);
      if (get().activeProjectId !== pid || latestProjectLoadSeq !== reqSeq) return;
      const [mapData, guardrails] = await Promise.all([
        fetchArchitectureMap(pid, get().c4Level),
        fetchGuardrailsReport(pid),
      ]);
      if (get().activeProjectId !== pid || latestProjectLoadSeq !== reqSeq) return;
      const impact = get().isDiffRadarActive ? await runVisualAiDiffImpact(pid) : null;
      if (get().activeProjectId !== pid || latestProjectLoadSeq !== reqSeq) return;
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
      if (get().activeProjectId !== pid || latestProjectLoadSeq !== reqSeq) return;
      set({ isLoading: false, errorMessage: err instanceof Error ? err.message : String(err) });
    }
  },

  setC4Level: async (level: number) => {
    const pid = get().activeProjectId;
    const reqSeq = latestProjectLoadSeq;
    set({ c4Level: level });
    if (!pid) return;
    set({ isLoading: true });
    try {
      const mapData = await fetchArchitectureMap(pid, level);
      if (get().activeProjectId !== pid || latestProjectLoadSeq !== reqSeq || get().c4Level !== level) return;
      set({ mapNodes: mapData.nodes, mapEdges: mapData.edges, isLoading: false });
    } catch (err) {
      if (get().activeProjectId !== pid || latestProjectLoadSeq !== reqSeq || get().c4Level !== level) return;
      set({ isLoading: false, errorMessage: err instanceof Error ? err.message : String(err) });
    }
  },

  selectNodeByUri: async (uri: string | null) => {
    const pid = get().activeProjectId;
    const reqSeq = latestProjectLoadSeq;
    const nodeSeq = ++latestNodeSelectSeq;
    if (!pid || !uri) {
      set({ selectedNode: null });
      return;
    }
    try {
      const { node } = await fetchNodePassport(pid, uri);
      if (get().activeProjectId !== pid || latestProjectLoadSeq !== reqSeq || latestNodeSelectSeq !== nodeSeq) return;
      set({ selectedNode: node });
    } catch (err) {
      if (get().activeProjectId !== pid || latestProjectLoadSeq !== reqSeq || latestNodeSelectSeq !== nodeSeq) return;
      set({ errorMessage: err instanceof Error ? err.message : String(err) });
    }
  },

  saveNoteForSelectedNode: async (summaryRu: string, riskLevel: RiskLevel): Promise<boolean> => {
    const pid = get().activeProjectId;
    const targetNode = get().selectedNode;
    if (!pid || !targetNode) return false;
    const reqSeq = latestProjectLoadSeq;
    const targetUri = targetNode.uri;
    try {
      const { node } = await saveNodeArchitecturalNote(pid, targetUri, summaryRu, riskLevel);
      if (get().activeProjectId !== pid || latestProjectLoadSeq !== reqSeq) return false;
      const currentLevel = get().c4Level;
      const mapData = await fetchArchitectureMap(pid, currentLevel);
      if (get().activeProjectId !== pid || latestProjectLoadSeq !== reqSeq) return false;
      set((state) => ({
        selectedNode: state.selectedNode?.uri === targetUri ? node : state.selectedNode,
        mapNodes: state.c4Level === currentLevel ? mapData.nodes : state.mapNodes,
        mapEdges: state.c4Level === currentLevel ? mapData.edges : state.mapEdges,
        errorMessage: null,
      }));
      return true;
    } catch (err) {
      if (get().activeProjectId !== pid || latestProjectLoadSeq !== reqSeq) return false;
      set({ errorMessage: err instanceof Error ? err.message : String(err) });
      return false;
    }
  },

  toggleDiffRadar: async () => {
    const pid = get().activeProjectId;
    const isDiffRadarActive = get().isDiffRadarActive;
    if (!pid) return;
    const reqSeq = latestProjectLoadSeq;
    if (isDiffRadarActive) {
      set({ isDiffRadarActive: false, impactReport: null });
      return;
    }
    set({ isLoading: true });
    try {
      const report = await runVisualAiDiffImpact(pid);
      if (get().activeProjectId !== pid || latestProjectLoadSeq !== reqSeq) return;
      set({ isDiffRadarActive: true, impactReport: report, isLoading: false });
    } catch (err) {
      if (get().activeProjectId !== pid || latestProjectLoadSeq !== reqSeq) return;
      set({ isLoading: false, errorMessage: err instanceof Error ? err.message : String(err) });
    }
  },

  toggleHealthRadar: () => set((s) => ({ isHealthRadarActive: !s.isHealthRadarActive })),
  setSearchQuery: (q: string) => set({ searchQuery: q }),
  setRiskFilter: (risk: 'all' | RiskLevel) => set({ riskFilter: risk }),
  clearError: () => set({ errorMessage: null }),
}));
