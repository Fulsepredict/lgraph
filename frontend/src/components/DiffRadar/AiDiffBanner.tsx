/**
 * Верхний баннер «Рентгена правок ИИ» (Visual AI Diff Overlay).
 *
 * Почему он нужен владельцу проекта после работы нейросети:
 * Одним взглядом без чтения сотен строк кода видно: сколько бизнес-модулей затронуто,
 * задет ли красный контур безопасности (🔴) и нет ли нарушений правил Guardrails.
 */

import { AlertOctagon, CheckCircle2, GitCompare, X } from 'lucide-react';
import { useGraphStore } from '../../store/useGraphStore';

export function AiDiffBanner() {
  const { isDiffRadarActive, impactReport, toggleDiffRadar } = useGraphStore();

  if (!isDiffRadarActive || !impactReport) {
    return null;
  }

  const hasDanger = impactReport.red_zone_touched || impactReport.guardrail_violations.length > 0;

  return (
    <div
      className={`px-4 py-2.5 border-b flex items-center justify-between gap-4 text-xs ${
        hasDanger
          ? 'bg-rose-950/40 border-rose-500/40 text-rose-100'
          : 'bg-zinc-900 border-amber-500/40 text-zinc-100'
      }`}
    >
      <div className="flex items-center gap-3 min-w-0">
        {hasDanger ? (
          <AlertOctagon className="w-4 h-4 text-rose-400 shrink-0" />
        ) : (
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
        )}
        <div className="min-w-0">
          <span className="font-semibold mr-2 inline-flex items-center gap-1">
            <GitCompare className="w-3.5 h-3.5" />
            Рентген последних правок Git:
          </span>
          <span className="text-zinc-200">{impactReport.summary_human_ru}</span>
        </div>
      </div>

      <button
        type="button"
        onClick={toggleDiffRadar}
        className="p-1 rounded hover:bg-zinc-800 text-zinc-400 hover:text-white shrink-0"
        title="Скрыть рентген правок"
      >
        <X className="w-4 h-4" />
      </button>
    </div>
  );
}
