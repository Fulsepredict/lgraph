/**
 * Центральная интерактивная карта архитектуры (`@xyflow/react` + `ELK.js`).
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
  type ReactFlowInstance,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { FolderOpen, Sparkles } from 'lucide-react';
import { useGraphStore } from '../../store/useGraphStore';
import { computeLayeredFlowLayout, type ArchitectureCardData } from '../../utils/elkLayout';
import { ArchitectureNodeCard } from './ArchitectureNodeCard';

const nodeTypes = {
  architectureCard: ArchitectureNodeCard,
};

export function ArchitectureMap() {
  const {
    activeProjectId,
    selfRootPath,
    mapNodes,
    mapEdges,
    c4Level,
    selectedNode,
    impactReport,
    isDiffRadarActive,
    isHealthRadarActive,
    searchQuery,
    riskFilter,
    isLoading,
    openProjectByPath,
    selectNodeByUri,
  } = useGraphStore();

  const [flowNodes, setFlowNodes] = useState<Array<Node<ArchitectureCardData>>>([]);
  const [flowEdges, setFlowEdges] = useState<Edge[]>([]);
  const rfInstanceRef = useRef<ReactFlowInstance<Node<ArchitectureCardData>, Edge> | null>(null);
  const lastFittedKeyRef = useRef<string>('');

  const filteredSourceNodes = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return mapNodes.filter((n) => {
      if (riskFilter !== 'all' && n.risk_level !== riskFilter) {
        return false;
      }
      if (!q) {
        return true;
      }
      return (
        n.name.toLowerCase().includes(q) ||
        n.rel_path.toLowerCase().includes(q) ||
        n.summary_ru.toLowerCase().includes(q) ||
        n.pattern_tag.toLowerCase().includes(q)
      );
    });
  }, [mapNodes, searchQuery, riskFilter]);

  useEffect(() => {
    let cancelled = false;
    if (!activeProjectId || filteredSourceNodes.length === 0) {
      setFlowNodes([]);
      setFlowEdges([]);
      return;
    }

    const modSet = new Set(isDiffRadarActive ? impactReport?.modified_c3_uris ?? [] : []);
    const impSet = new Set(isDiffRadarActive ? impactReport?.impacted_c3_uris ?? [] : []);

    computeLayeredFlowLayout({
      nodes: filteredSourceNodes,
      edges: mapEdges,
      c4Level,
      selectedUri: selectedNode?.uri ?? null,
      modifiedC3Uris: modSet,
      impactedC3Uris: impSet,
      showHealthRadar: isHealthRadarActive,
    }).then(({ flowNodes: nextN, flowEdges: nextE }) => {
      if (!cancelled) {
        setFlowNodes(nextN);
        setFlowEdges(nextE);
        const fitKey = `${activeProjectId}_${c4Level}_${nextN.length}`;
        if (lastFittedKeyRef.current !== fitKey) {
          lastFittedKeyRef.current = fitKey;
          setTimeout(() => {
            rfInstanceRef.current?.fitView({ padding: 0.14, duration: 220 });
          }, 40);
        }
      }
    });

    return () => {
      cancelled = true;
    };
  }, [
    activeProjectId,
    filteredSourceNodes,
    mapEdges,
    c4Level,
    selectedNode?.uri,
    impactReport,
    isDiffRadarActive,
    isHealthRadarActive,
  ]);

  const handlePickFolder = async () => {
    const chosen = await window.lgraphBridge?.pickProjectFolder();
    if (chosen) {
      await openProjectByPath(chosen);
    }
  };

  if (!activeProjectId) {
    return (
      <div className="flex-1 flex items-center justify-center bg-[#0E0E10] p-8">
        <div className="max-w-lg w-full rounded-2xl border border-zinc-800 bg-[#141417] p-7 text-center shadow-2xl">
          <img
            src="./logo.png"
            alt="Lgraph"
            className="w-20 h-20 mx-auto mb-4 object-contain"
          />
          <h2 className="text-lg font-semibold text-zinc-100 mb-2">
            Добро пожаловать в Lgraph 2.4
          </h2>
          <p className="text-xs text-zinc-400 leading-relaxed mb-6">
            Открой любой программный проект, чтобы за секунды увидеть понятную карту бизнес-модулей,
            светофор рисков (🔴/🟡/🟢), межъязыковые мосты и машинно-проверяемые правила для нейросети.
          </p>

          <div className="flex flex-col gap-2.5">
            <button
              onClick={handlePickFolder}
              className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg bg-zinc-100 text-zinc-950 font-medium text-xs hover:bg-white transition"
            >
              <FolderOpen className="w-4 h-4" />
              Выбрать папку проекта через проводник...
            </button>

            {selfRootPath && (
              <button
                type="button"
                onClick={() => openProjectByPath(selfRootPath)}
                className="w-full flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg border border-zinc-800 bg-[#1A1A1E] hover:border-zinc-600 text-zinc-200 text-xs transition"
              >
                <Sparkles className="w-3.5 h-3.5 text-zinc-400" />
                Открыть сам Lgraph (самодиагностика)
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 relative bg-[#0E0E10]">
      {isLoading && (
        <div className="absolute top-3 right-3 z-20 px-3 py-1.5 rounded-lg bg-zinc-900/90 border border-zinc-700 text-[11px] text-zinc-200">
          Сборка графа...
        </div>
      )}

      <ReactFlow
        nodes={flowNodes}
        edges={flowEdges}
        nodeTypes={nodeTypes}
        onInit={(inst) => {
          rfInstanceRef.current = inst;
        }}
        onNodeClick={(_ev, node) => selectNodeByUri(node.id)}
        onPaneClick={() => selectNodeByUri(null)}
        fitView
        fitViewOptions={{ padding: 0.14 }}
        minZoom={0.25}
        maxZoom={1.6}
      >
        <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#27272a" />
        <Controls showInteractive={false} />
        <MiniMap
          pannable
          zoomable
          maskColor="rgba(14, 14, 16, 0.82)"
          style={{ backgroundColor: '#141417', border: '1px solid #27272a', borderRadius: 8 }}
          nodeColor={(n) => {
            const risk = (n.data as ArchitectureCardData | undefined)?.dto?.risk_level;
            if (risk === 'critical') return '#f43f5e';
            if (risk === 'medium') return '#fbbf24';
            return '#52525b';
          }}
        />
      </ReactFlow>
    </div>
  );
}
