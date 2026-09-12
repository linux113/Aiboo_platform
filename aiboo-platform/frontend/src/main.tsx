import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App.tsx";
import ErrorBoundary from "./ErrorBoundary.tsx";

const rootElement = document.getElementById("root");

if (!rootElement) {
  document.body.innerHTML =
    '<div style="display:flex;align-items:center;justify-content:center;height:100vh;background:#020617;color:#94a3b8;font-family:sans-serif;font-size:14px">Root element not found</div>';
} else {
  createRoot(rootElement).render(
    <StrictMode>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </StrictMode>
  );
}
