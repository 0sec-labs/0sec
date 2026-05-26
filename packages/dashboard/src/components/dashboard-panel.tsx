import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

type DashboardPanelState = {
  title: string;
  description: string;
  content: ReactNode;
  onClose?: () => void;
};

type DashboardPanelContextValue = {
  panel: DashboardPanelState | null;
  openPanel: (panel: DashboardPanelState) => void;
  clearPanel: () => void;
  dismissPanel: () => void;
};

const DashboardPanelContext = createContext<DashboardPanelContextValue | null>(null);

export function DashboardPanelProvider({ children }: { children: ReactNode }) {
  const [panel, setPanel] = useState<DashboardPanelState | null>(null);
  const panelRef = useRef<DashboardPanelState | null>(null);

  useEffect(() => {
    panelRef.current = panel;
  }, [panel]);

  const openPanel = useCallback((nextPanel: DashboardPanelState) => {
    panelRef.current = nextPanel;
    setPanel(nextPanel);
  }, []);

  const clearPanel = useCallback(() => {
    panelRef.current = null;
    setPanel(null);
  }, []);

  const dismissPanel = useCallback(() => {
    const current = panelRef.current;
    panelRef.current = null;
    setPanel(null);
    current?.onClose?.();
  }, []);

  const value = useMemo(
    () => ({ panel, openPanel, clearPanel, dismissPanel }),
    [clearPanel, dismissPanel, openPanel, panel],
  );

  return (
    <DashboardPanelContext.Provider value={value}>
      {children}
    </DashboardPanelContext.Provider>
  );
}

export function useDashboardPanel() {
  const context = useContext(DashboardPanelContext);
  if (!context) {
    throw new Error("useDashboardPanel must be used within a DashboardPanelProvider.");
  }
  return context;
}
