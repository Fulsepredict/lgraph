/**
 * Верхняя панель управления Lgraph: фирменная сфера, кастомный переключатель проектов,
 * статус кэша SHA-256, тумблер «Рентгена правок ИИ» и «Радара здоровья».
 *
 * Важно: вместо нативного `<select>` используется кастомное графитовое меню,
 * чтобы избежать системных синих рамок Windows (правило GR-LGRAPH-UI-SELECT).
 */

import { useState } from 'react';
import {
  Activity,
  ChevronDown,
  FolderOpen,
  GitCompare,
  RefreshCw,
} from 'lucide-react';
import { useGraphStore } from '../../store/useGraphStore';

export function TopBar() {
  const {
    projects,
    activeProjectId,
    activeStats,
    lastIndexReport,
    isDiffRadarActive,
    isHealthRadarActive,
    isLoading,
    openProjectByPath,
    selectExistingProject,
    reindexActiveProject,
    toggleDiffRadar,
    toggleHealthRadar,
  } = useGraphStore();

  const [dropdownOpen, setDropdownOpen] = useState(false);
  const activeProj = activeStats?.project;

  const handleOpenDialog = async () => {
    setDropdownOpen(false);
    const chosen = await window.lgraphBridge?.pickProjectFolder();
    if (chosen) {
      await openProjectByPath(chosen);
    }
  };

  return (
    <header className="h-14 shrink-0 border-b border-zinc-800 bg-[#141417] px-4 flex items-center justify-between gap-4">
      {/* Левая группа: логотип-сфера Lgraph и выбор проекта */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2.5 pr-2 border-r border-zinc-800">
          <img
            src="./logo.png"
            alt="Lgraph"
            className="w-8 h-8 object-contain"
          />
          <div>
            <div className="text-sm font-bold tracking-tight text-zinc-100 leading-none">
              Lgraph
            </div>
            <div className="text-[10px] text-zinc-500 mt-0.5">Architecture & AI MCP</div>
          </div>
        </div>

        {/* Кастомный монохромный выпадающий список проектов */}
        <div className="relative">
          <button
            type="button"
            onClick={() => setDropdownOpen((v) => !v)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-zinc-800 bg-[#1A1A1E] hover:border-zinc-600 text-xs text-zinc-200 transition"
          >
            <span className="font-medium max-w-[200px] truncate">
              {activeProj ? activeProj.name : 'Проект не выбран'}
            </span>
            <ChevronDown className="w-3.5 h-3.5 text-zinc-400" />
          </button>

          {dropdownOpen && (
            <div className="absolute left-0 mt-1.5 w-72 rounded-xl border border-zinc-700 bg-[#18181C] shadow-2xl z-50 py-1.5">
              <div className="px-3 py-1 text-[10px] uppercase tracking-wider text-zinc-500">
                Недавние проекты
              </div>
              {projects.map((p) => (
                <button
                  key={p.project_id}
                  type="button"
                  onClick={() => {
                    setDropdownOpen(false);
                    selectExistingProject(p.project_id);
                  }}
                  className={`w-full text-left px-3 py-2 text-xs hover:bg-zinc-800/80 transition flex flex-col ${
                    p.project_id === activeProjectId ? 'bg-zinc-800/60 text-white' : 'text-zinc-300'
                  }`}
                >
                  <span className="font-medium">{p.name}</span>
                  <span className="text-[10px] text-zinc-500 truncate">{p.root_path}</span>
                </button>
              ))}
              <div className="border-t border-zinc-800 mt-1 pt-1 px-1.5">
                <button
                  type="button"
                  onClick={handleOpenDialog}
                  className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-xs text-zinc-200 hover:bg-zinc-800 transition"
                >
                  <FolderOpen className="w-3.5 h-3.5 text-zinc-400" />
                  Открыть другую папку...
                </button>
              </div>
            </div>
          )}
        </div>

        <button
          type="button"
          onClick={handleOpenDialog}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-zinc-800 bg-[#1A1A1E] hover:border-zinc-600 text-xs text-zinc-300 transition"
          title="Открыть папку проекта"
        >
          <FolderOpen className="w-3.5 h-3.5" />
          Открыть
        </button>
      </div>

      {/* Центральная сводка метрик индекса и кэша SHA-256 */}
      {activeStats && (
        <div className="hidden xl:flex items-center gap-4 text-[11px] text-zinc-400">
          <span>
            Узлов: <strong className="text-zinc-200">{activeStats.total_nodes}</strong>
          </span>
          <span>
            Связей: <strong className="text-zinc-200">{activeStats.total_edges}</strong>
          </span>
          <span>
            Ревизия: <strong className="text-zinc-200">#{activeStats.project.index_revision}</strong>
          </span>
          {lastIndexReport && (
            <span className="px-2 py-0.5 rounded bg-zinc-800/90 text-zinc-300">
              {lastIndexReport.elapsed_ms} мс (кэш SHA-256: {lastIndexReport.cache_hits})
            </span>
          )}
        </div>
      )}

      {/* Правая группа: Рентген правок ИИ, Радар здоровья и Переиндексация */}
      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={!activeProjectId || isLoading}
          onClick={toggleDiffRadar}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition ${
            isDiffRadarActive
              ? 'bg-amber-500/20 border-amber-400 text-amber-200'
              : 'bg-[#1A1A1E] border-zinc-800 text-zinc-300 hover:border-zinc-600 disabled:opacity-40'
          }`}
          title="Показать на карте, какие модули и контуры риска затронули последние правки Git"
        >
          <GitCompare className="w-3.5 h-3.5" />
          Рентген правок ИИ
        </button>

        <button
          type="button"
          disabled={!activeProjectId}
          onClick={toggleHealthRadar}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition ${
            isHealthRadarActive
              ? 'bg-zinc-200 text-zinc-950 border-zinc-200'
              : 'bg-[#1A1A1E] border-zinc-800 text-zinc-300 hover:border-zinc-600 disabled:opacity-40'
          }`}
          title="Подсвечивать раздутые файлы свыше 350 строк кода"
        >
          <Activity className="w-3.5 h-3.5" />
          Радар здоровья
        </button>

        <button
          type="button"
          disabled={!activeProjectId || isLoading}
          onClick={reindexActiveProject}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-zinc-800 bg-[#1A1A1E] hover:border-zinc-600 text-xs text-zinc-200 transition disabled:opacity-40"
          title="Обновить индекс графа"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          Обновить
        </button>
      </div>
    </header>
  );
}
