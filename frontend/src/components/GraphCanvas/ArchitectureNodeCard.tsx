/**
 * Карточка архитектурного узла на интерактивном холсте (`@xyflow/react`).
 *
 * Почему карточка выполнена в сдержанной графитовой палитре с точечным светофором:
 * Монохромный фон не утомляет глаза при анализе сложной системы, а цветные акценты
 * включаются только по делу: индикатор контура риска (🔴/🟡/🟢), плашка раздутого файла
 * («Радар здоровья») или контур «Рентгена правок ИИ».
 */

import { Handle, Position, type Node, type NodeProps } from '@xyflow/react';
import { AlertTriangle, FileCode2, Layers, ShieldAlert } from 'lucide-react';
import { cleanHumanDocText } from '../../services/api';
import type { ArchitectureCardData } from '../../utils/elkLayout';

const RISK_META = {
  critical: {
    dot: 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.75)]',
    label: 'КРИТИЧНЫЙ',
  },
  medium: {
    dot: 'bg-amber-400',
    label: 'ЛОГИКА / API',
  },
  low: {
    dot: 'bg-emerald-400',
    label: 'БАЗОВЫЙ',
  },
} as const;

export function ArchitectureNodeCard({ data }: NodeProps<Node<ArchitectureCardData>>) {
  const { dto, isSelected, isDiffModified, isDiffImpacted, showHealthRadar } = data;
  const risk = RISK_META[dto.risk_level] ?? RISK_META.low;
  const oversizedCount = dto.oversized_files?.length ?? 0;

  let borderClass = 'border-zinc-800 hover:border-zinc-600';
  if (isSelected) {
    borderClass = 'border-zinc-100 ring-2 ring-zinc-200/30';
  } else if (isDiffModified) {
    borderClass = 'border-amber-400 ring-2 ring-amber-400/30';
  } else if (isDiffImpacted) {
    borderClass = 'border-dashed border-zinc-400';
  }

  return (
    <div
      className={`w-[284px] min-h-[108px] rounded-xl bg-[#141417]/95 border ${borderClass} px-3.5 py-3 shadow-xl transition-all`}
    >
      <Handle type="target" position={Position.Left} className="!w-2 !h-2 !bg-zinc-400 !border-zinc-900" />

      <div className="flex items-center justify-between gap-2 mb-1.5">
        <div className="flex items-center gap-1.5 min-w-0">
          <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${risk.dot}`} title={`Риск: ${risk.label}`} />
          <span className="text-[10px] uppercase tracking-wider font-medium text-zinc-400 truncate">
            {dto.pattern_tag ? dto.pattern_tag.split('(')[0].trim() : dto.node_type}
          </span>
        </div>

        <div className="flex items-center gap-1 shrink-0">
          {isDiffModified && (
            <span className="px-1.5 py-0.5 text-[9px] font-semibold rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
              ИЗМЕНЁН
            </span>
          )}
          {!isDiffModified && isDiffImpacted && (
            <span className="px-1.5 py-0.5 text-[9px] font-medium rounded bg-zinc-800 text-zinc-300 border border-zinc-600">
              ЗАДЕТ
            </span>
          )}
          {showHealthRadar && oversizedCount > 0 && (
            <span
              className="flex items-center gap-0.5 px-1.5 py-0.5 text-[9px] font-semibold rounded bg-rose-500/15 text-rose-300 border border-rose-500/30"
              title={`Файлов > 350 строк: ${oversizedCount}`}
            >
              <AlertTriangle className="w-2.5 h-2.5" />
              {oversizedCount}
            </span>
          )}
        </div>
      </div>

      <div className="text-[13px] font-semibold text-zinc-100 leading-snug line-clamp-1 mb-1">
        {dto.name}
      </div>

      <div className="text-[11px] text-zinc-400 leading-relaxed line-clamp-2 min-h-[30px]">
        {cleanHumanDocText(dto.summary_ru) || dto.rel_path || dto.uri}
      </div>

      <div className="mt-2 pt-1.5 border-t border-zinc-800/80 flex items-center justify-between text-[10px] text-zinc-500">
        <span className="flex items-center gap-1 truncate max-w-[180px]">
          {dto.c4_level <= 3 ? <Layers className="w-3 h-3 shrink-0" /> : <FileCode2 className="w-3 h-3 shrink-0" />}
          {dto.rel_path || `Уровень C${dto.c4_level}`}
        </span>
        <span className="flex items-center gap-1 shrink-0">
          {Boolean(dto.meta?.has_redacted_secret) && (
            <span title="Обнаружен и скрыт секрет в коде">
              <ShieldAlert className="w-3 h-3 text-rose-400" />
            </span>
          )}
          {typeof dto.file_count === 'number' && dto.file_count > 0 ? `${dto.file_count} файл.` : ''}
        </span>
      </div>

      <Handle type="source" position={Position.Right} className="!w-2 !h-2 !bg-zinc-400 !border-zinc-900" />
    </div>
  );
}
