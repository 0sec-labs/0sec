import { useEffect, useEffectEvent } from "react";
import type { DesktopHostCommand } from "@0sec/shared";

const SHORTCUTS: Readonly<Record<string, DesktopHostCommand>> = {
  n: "new-thread",
  o: "open-folder",
  b: "toggle-sidebar",
  ",": "settings",
};

export function useKeyboardShortcuts(handler: (command: DesktopHostCommand) => void): void {
  const onCommand = useEffectEvent(handler);

  useEffect(() => {
    // Electron's native menu owns these accelerators. A second DOM listener
    // would race it and can create duplicate threads or toggle twice.
    if (window.osecDesktop) return window.osecDesktop.onCommand(onCommand);

    const isMac = navigator.platform.includes("Mac");
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.defaultPrevented || event.isComposing || event.altKey || event.shiftKey) return;
      if (!(isMac ? event.metaKey : event.ctrlKey)) return;
      const command = SHORTCUTS[event.key.toLowerCase()];
      if (!command) return;
      event.preventDefault();
      onCommand(command);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);
}
