import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";

const ChatPage = lazy(async () => ({ default: (await import("@/pages/chat-page")).ChatPage }));
const OperationsApp = lazy(async () => ({ default: (await import("@/pages/operations-app")).OperationsApp }));

function LoadingWorkspace({ label }: { label: string }) {
  return <div className="grid min-h-screen place-items-center bg-background text-sm text-muted-foreground">{label}</div>;
}

export function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/chat" replace />} />
      <Route
        path="/chat"
        element={(
          <Suspense fallback={<LoadingWorkspace label="Opening operator workspace…" />}>
            <ChatPage />
          </Suspense>
        )}
      />
      <Route
        path="*"
        element={(
          <Suspense fallback={<LoadingWorkspace label="Opening operations…" />}>
            <OperationsApp />
          </Suspense>
        )}
      />
    </Routes>
  );
}
