/**
 * Корневой каркас окна Lgraph: верхняя панель, баннер «Рентгена правок ИИ» и 3 рабочие области.
 */

import { useEffect } from 'react';
import { AlertCircle, X } from 'lucide-react';
import { AiDiffBanner } from './components/DiffRadar/AiDiffBanner';
import { ArchitectureMap } from './components/GraphCanvas/ArchitectureMap';
import { NodePassportPanel } from './components/Inspector/NodePassportPanel';
import { TopBar } from './components/Layout/TopBar';
import { NavigationSidebar } from './components/Sidebar/NavigationSidebar';
import { useGraphStore } from './store/useGraphStore';

export function App() {
  const { bootInitialProjects, openProjectByPath, errorMessage, clearError } = useGraphStore();

  useEffect(() => {
    bootInitialProjects();
  }, [bootInitialProjects]);

  useEffect(() => {
    const unsubscribe = window.lgraphBridge?.onExternalOpenFolder((folderPath) => {
      if (folderPath) {
        void openProjectByPath(folderPath);
      }
    });
    return () => {
      unsubscribe?.();
    };
  }, [openProjectByPath]);

  return (
    <div className="h-screen w-screen flex flex-col bg-[#0E0E10] text-zinc-100 overflow-hidden">
      <TopBar />
      <AiDiffBanner />

      {errorMessage && (
        <div className="px-4 py-2 bg-rose-950/70 border-b border-rose-500/40 text-xs text-rose-200 flex items-center justify-between">
          <span className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            {errorMessage}
          </span>
          <button type="button" onClick={clearError} className="p-1 hover:text-white">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      <main className="flex-1 flex min-h-0 overflow-hidden">
        <NavigationSidebar />
        <ArchitectureMap />
        <NodePassportPanel />
      </main>
    </div>
  );
}
