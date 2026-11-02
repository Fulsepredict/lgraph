/**
 * Автоматическая слоистая укладка архитектурной карты на базе ELK.js (`layered`).
 *
 * Почему здесь применён `ELK.js` вместо физического "пружинного" графа:
 * Пружинные графы постоянно дёргаются и сваливают узлы в паутину. Слоистый алгоритм
 * раскладывает систему как чистый инженерный чертёж слева направо (`UI -> IPC -> Backend`),
 * гарантируя отсутствие наложений карточек друг на друга.
 */

import ELK from 'elkjs/lib/elk.bundled.js';
import type { Edge, Node } from '@xyflow/react';
import type { GraphEdgeDto, GraphNodeDto } from '../types/graph';

const elk = new ELK();

const CARD_WIDTH = 284;
const CARD_HEIGHT = 112;

export interface ArchitectureCardData extends Record<string, unknown> {
  dto: GraphNodeDto;
  isSelected: boolean;
  isDiffModified: boolean;
  isDiffImpacted: boolean;
  showHealthRadar: boolean;
}

export async function computeLayeredFlowLayout(params: {
  nodes: GraphNodeDto[];
  edges: GraphEdgeDto[];
  c4Level: number;
  selectedUri: string | null;
  modifiedC3Uris: Set<string>;
  impactedC3Uris: Set<string>;
  showHealthRadar: boolean;
}): Promise<{ flowNodes: Array<Node<ArchitectureCardData>>; flowEdges: Edge[] }> {
  const {
    nodes,
    edges,
    c4Level,
    selectedUri,
    modifiedC3Uris,
    impactedC3Uris,
    showHealthRadar,
  } = params;

  // Показываем на холсте именно целевой выбранный слой (например, на C3 — чистые Бизнес-модули без контейнеров-матрёшек),
  // чтобы стрелки между модулями читались с первого взгляда. На C4 ограничиваемся файлами и мостами, чтобы холст летал.
  let visibleDtos = nodes.filter((n) =>
    c4Level < 4
      ? n.c4_level === c4Level
      : n.node_type === 'File' || n.source_module === 'bridge_linker'
  );
  if (visibleDtos.length === 0) {
    visibleDtos = nodes;
  }
  // Защитный предел отрисовки на уровне C4 для мгновенного отклика
  if (visibleDtos.length > 140) {
    visibleDtos = visibleDtos.slice(0, 140);
  }

  const visibleUriSet = new Set(visibleDtos.map((n) => n.uri));
  const semanticEdges = edges.filter(
    (e) =>
      e.edge_type !== 'CONTAINS' &&
      e.src_uri !== e.dst_uri &&
      visibleUriSet.has(e.src_uri) &&
      visibleUriSet.has(e.dst_uri)
  );

  const elkGraph = {
    id: 'lgraph-root',
    layoutOptions: {
      'elk.algorithm': 'layered',
      'elk.direction': 'RIGHT',
      'elk.spacing.nodeNode': '42',
      'elk.layered.spacing.nodeNodeBetweenLayers': '96',
      'elk.edgeRouting': 'SPLINES',
    },
    children: visibleDtos.map((n) => ({
      id: n.uri,
      width: CARD_WIDTH,
      height: CARD_HEIGHT,
    })),
    edges: semanticEdges.map((e, idx) => ({
      id: `e_${idx}_${e.src_uri}_${e.dst_uri}`,
      sources: [e.src_uri],
      targets: [e.dst_uri],
    })),
  };

  const laidOut = await elk.layout(elkGraph);
  const posByUri = new Map<string, { x: number; y: number }>();
  for (const child of laidOut.children ?? []) {
    posByUri.set(child.id, { x: child.x ?? 0, y: child.y ?? 0 });
  }

  const flowNodes: Array<Node<ArchitectureCardData>> = visibleDtos.map((dto) => ({
    id: dto.uri,
    type: 'architectureCard',
    position: posByUri.get(dto.uri) ?? { x: 0, y: 0 },
    data: {
      dto,
      isSelected: selectedUri === dto.uri,
      isDiffModified: modifiedC3Uris.has(dto.uri),
      isDiffImpacted: impactedC3Uris.has(dto.uri),
      showHealthRadar,
    },
  }));

  const flowEdges: Edge[] = semanticEdges.map((e, idx) => {
    const isBridge = e.edge_type === 'BRIDGES_TO' || e.edge_type === 'USES_CONTRACT';
    const isDynamic = e.confidence_tier === 'unresolved_dynamic';
    return {
      id: `flow_e_${idx}_${e.src_uri}_${e.dst_uri}`,
      source: e.src_uri,
      target: e.dst_uri,
      animated: isBridge,
      label: isBridge ? (isDynamic ? '⚠ ДИНАМИЧЕСКИЙ IPC' : e.evidence || 'МОСТ API/IPC') : undefined,
      labelStyle: { fill: '#f4f4f5', fontSize: 10, fontWeight: 600 },
      labelBgStyle: { fill: '#18181b', fillOpacity: 0.92, stroke: '#3f3f46' },
      labelBgPadding: [6, 3],
      labelBgBorderRadius: 4,
      style: {
        stroke: isDynamic ? '#f59e0b' : isBridge ? '#e4e4e7' : '#52525b',
        strokeWidth: isBridge ? 2.2 : 1.4,
        strokeDasharray: isBridge ? '6 4' : undefined,
      },
    };
  });

  return { flowNodes, flowEdges };
}
