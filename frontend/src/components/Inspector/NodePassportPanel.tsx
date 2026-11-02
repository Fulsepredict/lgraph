/**
 * Правая двуязычная панель Инспектора узла («Паспорт модуля»).
 *
 * Почему здесь ровно две вкладки («Простым языком» и «Техпаспорт»):
 * 1. Вкладка «Простым языком» открыта по умолчанию: показывает светофор риска,
 *    обучающую карточку IT-паттерна без жаргона и даёт сохранить свою заметку.
 * 2. Вкладка «Техпаспорт» даёт точные пути, строки, сигнатуры, переходы по связям
 *    и кнопку открытия файла в редакторе.
 */

import { useEffect, useState } from 'react';
import {
  ArrowLeftRight,
  BookOpen,
  Code2,
  ExternalLink,
  Save,
  X,
} from 'lucide-react';
import { useGraphStore } from '../../store/useGraphStore';
import { cleanHumanDocText } from '../../services/api';
import type { RiskLevel } from '../../types/graph';

const RISK_EXPLANATIONS: Record<RiskLevel, { badge: string; desc: string }> = {
  critical: {
    badge: '🔴 Критический контур безопасности',
    desc: 'Этот узел отвечает за защиту периметра, секреты, токены, прокси или критические операции. Любые правки ИИ здесь требуют повышенного внимания.',
  },
  medium: {
    badge: '🟡 Рабочая бизнес-логика и контракты API',
    desc: 'Управляет потоками данных, маршрутами запросов или хранением состояния. При изменении важно не нарушить контракт между фронтендом и сервером.',
  },
  low: {
    badge: '🟢 Безопасный визуальный / вспомогательный блок',
    desc: 'Локальное оформление экрана или чистая утилита. Ошибка здесь не сломает безопасность или базу данных.',
  },
};

export function NodePassportPanel() {
  const {
    selectedNode,
    activeStats,
    selectNodeByUri,
    saveNoteForSelectedNode,
  } = useGraphStore();

  const [activeTab, setActiveTab] = useState<'human' | 'tech'>('human');
  const [noteText, setNoteText] = useState('');
  const [riskChoice, setRiskChoice] = useState<RiskLevel>('low');
  const [savedToast, setSavedToast] = useState(false);

  useEffect(() => {
    if (selectedNode) {
      setNoteText(cleanHumanDocText(selectedNode.summary_ru));
      setRiskChoice(selectedNode.risk_level || 'low');
      setSavedToast(false);
    }
  }, [selectedNode]);

  if (!selectedNode) {
    return null;
  }

  const riskInfo = RISK_EXPLANATIONS[selectedNode.risk_level] ?? RISK_EXPLANATIONS.low;
  const inbound = selectedNode.inbound_edges ?? [];
  const outbound = selectedNode.outbound_edges ?? [];

  const handleSaveNote = async () => {
    await saveNoteForSelectedNode(noteText, riskChoice);
    setSavedToast(true);
    setTimeout(() => setSavedToast(false), 2200);
  };

  const handleOpenInEditor = async () => {
    const rootPath = activeStats?.project?.root_path;
    if (rootPath && selectedNode.rel_path) {
      await window.lgraphBridge?.openFileInEditor({
        rootPath,
        relPath: selectedNode.rel_path,
      });
    }
  };

  return (
    <aside className="w-96 shrink-0 border-l border-zinc-800 bg-[#141417] flex flex-col h-full overflow-hidden">
      {/* Шапка инспектора */}
      <div className="p-3.5 border-b border-zinc-800 flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="text-[10px] uppercase tracking-wider text-zinc-500 font-semibold">
            {selectedNode.node_type} · Уровень C{selectedNode.c4_level}
          </div>
          <h3 className="text-sm font-semibold text-zinc-100 truncate mt-0.5">
            {selectedNode.name}
          </h3>
        </div>
        <button
          type="button"
          onClick={() => selectNodeByUri(null)}
          className="p-1 rounded-lg text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 transition"
          title="Закрыть паспорт"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Переключатель двух вкладок */}
      <div className="grid grid-cols-2 gap-1 p-2 bg-[#0E0E10] border-b border-zinc-800">
        <button
          type="button"
          onClick={() => setActiveTab('human')}
          className={`flex items-center justify-center gap-1.5 py-1.5 rounded-md text-xs font-medium transition ${
            activeTab === 'human'
              ? 'bg-zinc-200 text-zinc-950'
              : 'text-zinc-400 hover:text-zinc-200'
          }`}
        >
          <BookOpen className="w-3.5 h-3.5" />
          Простым языком
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('tech')}
          className={`flex items-center justify-center gap-1.5 py-1.5 rounded-md text-xs font-medium transition ${
            activeTab === 'tech'
              ? 'bg-zinc-200 text-zinc-950'
              : 'text-zinc-400 hover:text-zinc-200'
          }`}
        >
          <Code2 className="w-3.5 h-3.5" />
          Техпаспорт
        </button>
      </div>

      {/* Контент вкладки */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {activeTab === 'human' ? (
          <>
            {/* Светофор риска */}
            <div className="p-3 rounded-xl bg-[#0E0E10] border border-zinc-800 space-y-1">
              <div className="text-xs font-semibold text-zinc-100">{riskInfo.badge}</div>
              <p className="text-[11px] text-zinc-400 leading-relaxed">{riskInfo.desc}</p>
            </div>

            {/* Обучающая карточка IT-паттерна */}
            {selectedNode.pattern_tag && (
              <div className="p-3 rounded-xl bg-[#1A1A1E] border border-zinc-700/70 space-y-1.5">
                <div className="text-[10px] uppercase tracking-wider text-zinc-400 font-semibold">
                  🎓 Как устроен этот IT-паттерн
                </div>
                <div className="text-xs font-semibold text-zinc-100">
                  {selectedNode.pattern_tag}
                </div>
                <p className="text-[11px] text-zinc-300 leading-relaxed">
                  {cleanHumanDocText(selectedNode.summary_ru) || 'Архитектурный узел системы.'}
                </p>
              </div>
            )}

            {/* Долговременная заметка (не затирается при переиндексации!) */}
            <div className="space-y-2">
              <label className="block text-[11px] font-medium text-zinc-300">
                Паспорт смысла (сохраняется в память для тебя и для ИИ):
              </label>
              <textarea
                rows={4}
                value={noteText}
                onChange={(e) => setNoteText(e.target.value)}
                placeholder="Опиши своими словами, за что отвечает этот модуль..."
                className="w-full rounded-lg bg-[#0E0E10] border border-zinc-800 focus:border-zinc-500 focus:outline-none p-2.5 text-xs text-zinc-200 leading-relaxed resize-none"
              />

              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-1">
                  {(['low', 'medium', 'critical'] as RiskLevel[]).map((r) => (
                    <button
                      key={r}
                      type="button"
                      onClick={() => setRiskChoice(r)}
                      className={`px-2 py-1 rounded text-[10px] border transition ${
                        riskChoice === r
                          ? 'bg-zinc-800 border-zinc-400 text-white'
                          : 'bg-[#0E0E10] border-zinc-800 text-zinc-400'
                      }`}
                    >
                      {r === 'critical' ? '🔴 Риск' : r === 'medium' ? '🟡 Логика' : '🟢 База'}
                    </button>
                  ))}
                </div>

                <button
                  type="button"
                  onClick={handleSaveNote}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-100 text-zinc-950 hover:bg-white text-xs font-medium transition"
                >
                  <Save className="w-3.5 h-3.5" />
                  {savedToast ? 'Сохранено!' : 'Сохранить'}
                </button>
              </div>
            </div>
          </>
        ) : (
          <>
            {/* Точные координаты файла и переход в IDE */}
            <div className="p-3 rounded-xl bg-[#0E0E10] border border-zinc-800 space-y-2">
              <div className="text-[10px] uppercase text-zinc-500">Канонический URI</div>
              <div className="text-[11px] font-mono text-zinc-200 break-all">{selectedNode.uri}</div>

              {selectedNode.rel_path && (
                <div className="pt-1 flex items-center justify-between gap-2">
                  <span className="text-[11px] text-zinc-400 truncate">
                    {selectedNode.rel_path}
                    {selectedNode.start_line > 0 ? `:${selectedNode.start_line}-${selectedNode.end_line}` : ''}
                  </span>
                  <button
                    type="button"
                    onClick={handleOpenInEditor}
                    title="Показать файл в Проводнике"
                    className="shrink-0 flex items-center gap-1 px-2 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-[11px] text-zinc-100 transition"
                  >
                    <ExternalLink className="w-3 h-3" />
                    Показать файл
                  </button>
                </div>
              )}

              {selectedNode.signature && (
                <pre className="mt-2 p-2 rounded bg-[#141417] border border-zinc-800 text-[10px] text-zinc-300 overflow-x-auto">
                  {selectedNode.signature}
                </pre>
              )}
            </div>

            {/* Входящие связи */}
            <div className="space-y-1.5">
              <div className="text-[11px] font-semibold text-zinc-300 flex items-center gap-1.5">
                <ArrowLeftRight className="w-3.5 h-3.5 text-zinc-400" />
                Кто зависит от этого узла ({inbound.length})
              </div>
              <div className="space-y-1 max-h-40 overflow-y-auto">
                {inbound.map((e, i) => (
                  <button
                    key={`in_${i}`}
                    type="button"
                    onClick={() => selectNodeByUri(e.src_uri)}
                    className="w-full text-left p-2 rounded-lg bg-[#0E0E10] hover:bg-zinc-800/70 border border-zinc-800 text-[11px] transition"
                  >
                    <div className="font-mono text-zinc-200 truncate">{e.src_uri}</div>
                    <div className="text-[10px] text-zinc-500">
                      [{e.edge_type}] · {e.confidence_tier} {e.evidence ? `· ${e.evidence}` : ''}
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Исходящие связи */}
            <div className="space-y-1.5">
              <div className="text-[11px] font-semibold text-zinc-300">
                От кого зависит этот узел ({outbound.length})
              </div>
              <div className="space-y-1 max-h-40 overflow-y-auto">
                {outbound.map((e, i) => (
                  <button
                    key={`out_${i}`}
                    type="button"
                    onClick={() => selectNodeByUri(e.dst_uri)}
                    className="w-full text-left p-2 rounded-lg bg-[#0E0E10] hover:bg-zinc-800/70 border border-zinc-800 text-[11px] transition"
                  >
                    <div className="font-mono text-zinc-200 truncate">{e.dst_uri}</div>
                    <div className="text-[10px] text-zinc-500">
                      [{e.edge_type}] · {e.confidence_tier} {e.evidence ? `· ${e.evidence}` : ''}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </>
        )}
      </div>
    </aside>
  );
}
