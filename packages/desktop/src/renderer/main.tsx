import { Component, StrictMode, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource/ibm-plex-mono/400.css";
import { DesktopApp } from "./app";
import "./app.css";

class DesktopBoundary extends Component<
  { children: ReactNode },
  { error: string | null }
> {
  state = { error: null as string | null };
  static getDerivedStateFromError(error: unknown) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
  render() {
    if (this.state.error)
      return (
        <main className="startup-error" role="alert">
          <h1>Unable to open your workspace</h1>
          <p>{this.state.error}</p>
          <button onClick={() => window.location.reload()}>
            Reload workspace
          </button>
        </main>
      );
    return this.props.children;
  }
}

const root = createRoot(document.getElementById("root")!);

async function startDesktop(): Promise<void> {
  try {
    if (window.osecDesktop) {
      const preferences = await window.osecDesktop.getPreferences();
      for (const [key, value] of Object.entries(preferences)) {
        if (key.startsWith("0sec:"))
          localStorage.setItem(key, JSON.stringify(value));
      }
    }
    root.render(
      <StrictMode>
        <DesktopBoundary>
          <DesktopApp />
        </DesktopBoundary>
      </StrictMode>,
    );
  } catch (error) {
    root.render(
      <main className="startup-error" role="alert">
        <h1>Unable to load your workspace</h1>
        <p>{error instanceof Error ? error.message : String(error)}</p>
        <button onClick={() => void startDesktop()}>Try again</button>
      </main>,
    );
  }
}

void startDesktop();
