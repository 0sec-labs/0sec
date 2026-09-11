import { lazy, Suspense } from "react";
const OperationsApp = lazy(async () => ({ default: (await import("@/pages/operations-app")).OperationsApp }));

function LoadingWorkspace({ label }: { label: string }) {
  return (
    <div
      role="status"
      className="grid min-h-screen place-items-center text-sm"
      style={{
        colorScheme: "light dark",
        background: "Canvas",
        color: "CanvasText",
        fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
      }}
    >
      {label}
    </div>
  );
}

export function App() {
  return (
    <Suspense fallback={<LoadingWorkspace label="Opening operations…" />}>
      <OperationsApp />
    </Suspense>
  );
}
