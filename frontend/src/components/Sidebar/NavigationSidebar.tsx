/**
 * Левая панель навигации Lgraph:
 * 1) Переключатель масштаба C1..C4 (по умолчанию C3 — Бизнес-модули, без шума функций).
 * 2) Поиск по русским смыслам, путям и названиям.
 * 3) Светофор фильтрации риска (Все / 🔴 / 🟡 / 🟢).
 * 4) Живой щит машинно-проверяемых правил GuardrailEngine с объяснением нарушений.
 */

import { useEffect, useState } from 'react';
import { CheckCircle2, FileSearch, Search, ShieldAlert, ShieldCheck } from 'lucide-react';
import {
  cleanHumanDocText,
  resolvePathOrUriToNodeUri,
  searchProjectNodes,
} from '../../services/api';
import { useGraphStore } from '../../store/useGraphStore';
import type { GraphNodeDto, RiskLevel } from '../../types/graph';

const C4_LEVELS = [
  { level: 2, short: 'C2', title: 'Контейнеры', hint: 'Клиент / Electron / Сервер' },
  { level: 3, short: 'C3', title: 'Бизнес-модули', hint: 'Рекомендуемый вид' },
  { level: 4, short: 'C4', title: 'Файлы и мосты', hint: 'Детальный слой кода' },
];

export function NavigationSidebar() {
  const {
    activeProjectId,
    c4Level,
    mapNodes,
    selectedNode,
    guardrailsReport,
    searchQuery,
    riskFilter,
    setC4Level,
    selectNodeByUri,
    setSearchQuery,
    setRiskFilter,
  } = useGraphStore();

  const [showViolationsModal, setShowViolationsModal] = useState(false);
  const [ftsHits, setFtsHits] = useState<GraphNodeDto[]>([]);

  useEffect(() => {
    const trimmed = searchQuery.trim();
    if (!activeProjectId || trimmed.length < 2) {
      setFtsHits([]);
      return;
    }
    let cancelled = false;
    const timer = setTimeout(() => {
      searchProjectNodes(activeProjectId, trimmed, 18)
        .then(({ results }) => {
          if (!cancelled) setFtsHits(results);
        })
        .catch(() => {
          if (!cancelled) setFtsHits([]);
        });
    }, 180);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [activeProjectId, searchQuery]);

  if (!activeProjectId) {
    return null;
  }

  const levelNodes = mapNodes
    .filter((n) => (c4Level < 4 ? n.c4_level === c4Level : n.node_type === 'File'))
    .filter((n) => (riskFilter === 'all' ? true : n.risk_level === riskFilter))
    .filter((n) => {
      const q = searchQuery.trim().toLowerCase();
      if (!q) return true;
      return (
        n.name.toLowerCase().includes(q) ||
        n.rel_path.toLowerCase().includes(q) ||
        cleanHumanDocText(n.summary_ru).toLowerCase().includes(q)
      );
    });

  const violationsCount = guardrailsReport?.violations.length ?? 0;

  return (
    <aside className="w-72 shrink-0 border-r border-zinc-800 bg-[#141417] flex flex-col h-full overflow-hidden">
      {/* Переключатель масштаба C2 / C3 / C4 */}
      <div className="p-3 border-b border-zinc-800">
        <div className="text-[10px] uppercase tracking-wider text-zinc-500 font-semibold mb-2">
          Масштаб карты (C4 Zoom)
        </div>
        <div className="grid grid-cols-3 gap-1 bg-[#0E0E10] p-1 rounded-lg border border-zinc-800">
          {C4_LEVELS.map((item) => {
            const active = c4Level === item.level;
            return (
              <button
                key={item.level}
                type="button"
                onClick={() => setC4Level(item.level)}
                title={`${item.title} — ${item.hint}`}
                className={`py-1.5 px-2 rounded-md text-center transition ${
                  active
                    ? 'bg-zinc-200 text-zinc-950 font-semibold'
                    : 'text-zinc-400 hover:text-zinc-200'
                }`}
              >
                <div className="text-xs leading-none">{item.short}</div>
                <div className="text-[9px] mt-0.5 truncate opacity-80">{item.title}</div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Поиск и фильтр светофора риска */}
      <div className="p-3 border-b border-zinc-800 space-y-2.5">
        <div className="relative">
          <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Поиск по модулям и смыслу..."
            className="w-full pl-8 pr-2.5 py-1.5 rounded-lg bg-[#0E0E10] border border-zinc-800 focus:border-zinc-500 focus:outline-none text-xs text-zinc-200 placeholder:text-zinc-600"
          />
        </div>

        <div className="flex items-center gap-1">
          {(
            [
              { id: 'all', label: 'Все' },
              { id: 'critical', label: '🔴 Риск' },
              { id: 'medium', label: '🟡 Логика' },
              { id: 'low', label: '🟢 База' },
            ] as Array<{ id: 'all' | RiskLevel; label: string }>
          ).map((f) => (
            <button
              key={f.id}
              type="button"
              onClick={() => setRiskFilter(f.id)}
              className={`flex-1 py-1 rounded-md text-[10px] font-medium border transition ${
                riskFilter === f.id
                  ? 'bg-zinc-800 border-zinc-500 text-zinc-100'
                  : 'bg-[#0E0E10] border-zinc-800/80 text-zinc-400 hover:text-zinc-200'
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      {/* Щит машинно-проверяемых правил GuardrailEngine */}
      {guardrailsReport && (
        <div className="p-3 border-b border-zinc-800">
          <button
            type="button"
            onClick={() => setShowViolationsModal((v) => !v)}
            className={`w-full flex items-center justify-between px-3 py-2 rounded-lg border text-xs transition ${
              violationsCount === 0
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                : 'bg-rose-500/10 border-rose-500/40 text-rose-300'
            }`}
          >
            <span className="flex items-center gap-2 font-medium">
              {violationsCount === 0 ? (
                <ShieldCheck className="w-4 h-4 shrink-0" />
              ) : (
                <ShieldAlert className="w-4 h-4 shrink-0" />
              )}
              Правила Guardrails
            </span>
            <span className="font-semibold">
              {violationsCount === 0
                ? `${guardrailsReport.rules.length || 2} ОК`
                : `${violationsCount} наруш.`}
            </span>
          </button>

          {showViolationsModal && (
            <div className="mt-2 max-h-52 overflow-y-auto space-y-2 pr-1">
              {violationsCount === 0 ? (
                <div className="p-2.5 rounded-lg bg-[#0E0E10] border border-zinc-800 text-[11px] text-zinc-400 flex items-start gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                  <span>Все машинно-проверяемые архитектурные ограничения соблюдены.</span>
                </div>
              ) : (
                guardrailsReport.violations.map((v, idx) => (
                  <button
                    key={`${v.rule_id}_${idx}`}
                    type="button"
                    onClick={() => selectNodeByUri(resolvePathOrUriToNodeUri(v.target_uri_or_path))}
                    title="Открыть техпаспорт этого файла в правой панели"
                    className="w-full text-left p-2.5 rounded-lg bg-[#0E0E10] hover:bg-zinc-900 border border-rose-500/30 hover:border-rose-400/60 text-[11px] space-y-1 transition"
                  >
                    <div className="font-semibold text-rose-300">
                      [{v.rule_id}] {v.title}
                    </div>
                    <div className="text-zinc-200 font-mono text-[10px] break-all underline decoration-zinc-600">
                      {v.target_uri_or_path}:{v.line_number}
                    </div>
                    <div className="text-zinc-400">{v.why_violated_ru}</div>
                    <div className="text-emerald-300/90">💡 {v.how_to_fix_ru}</div>
                  </button>
                ))
              )}
            </div>
          )}
        </div>
      )}

      {/* Глубокий полнотекстовый поиск FTS5 по функциям, классам и файлам внутри модулей */}
      {searchQuery.trim().length >= 2 && ftsHits.length > 0 && (
        <div className="p-2 border-b border-zinc-800 max-h-48 overflow-y-auto space-y-1 bg-[#101013]">
          <div className="px-2 py-0.5 text-[10px] uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
            <FileSearch className="w-3 h-3" />
            Найдено внутри кода ({ftsHits.length})
          </div>
          {ftsHits.map((hit) => (
            <button
              key={`fts_${hit.uri}`}
              type="button"
              onClick={() => selectNodeByUri(hit.uri)}
              className="w-full text-left px-2.5 py-1.5 rounded-lg text-xs hover:bg-zinc-800/70 text-zinc-200 transition"
            >
              <div className="font-medium truncate">
                {hit.name} <span className="text-[10px] text-zinc-500">· {hit.node_type}</span>
              </div>
              <div className="text-[10px] text-zinc-500 truncate">{hit.rel_path || hit.uri}</div>
            </button>
          ))}
        </div>
      )}

      {/* Список видимых узлов текущего уровня */}
      <div className="flex-1 overflow-y-auto p-2 space-y-1">
        <div className="px-2 py-1 text-[10px] uppercase tracking-wider text-zinc-500">
          Элементы на карте ({levelNodes.length})
        </div>
        {levelNodes.map((n) => {
          const isSel = selectedNode?.uri === n.uri;
          const dotColor =
            n.risk_level === 'critical'
              ? 'bg-rose-500'
              : n.risk_level === 'medium'
              ? 'bg-amber-400'
              : 'bg-emerald-400';
          return (
            <button
              key={n.uri}
              type="button"
              onClick={() => selectNodeByUri(n.uri)}
              className={`w-full text-left px-2.5 py-2 rounded-lg text-xs transition flex items-start gap-2 ${
                isSel
                  ? 'bg-zinc-800 text-white border border-zinc-600'
                  : 'text-zinc-300 hover:bg-zinc-800/50 border border-transparent'
              }`}
            >
              <span className={`w-2 h-2 rounded-full shrink-0 mt-1 ${dotColor}`} />
              <div className="min-w-0 flex-1">
                <div className="font-medium truncate">{n.name}</div>
                <div className="text-[10px] text-zinc-500 truncate">{n.rel_path || n.node_type}</div>
              </div>
            </button>
          );
        })}
      </div>
    </aside>
  );
}
