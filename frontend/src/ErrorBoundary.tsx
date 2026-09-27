import React from "react";

interface Props {
  children: React.ReactNode;
}

interface State {
  hasError: boolean;
  error?: Error;
}

export default class ErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo): void {
    console.error("[ErrorBoundary] Caught error:", error);
    console.error("[ErrorBoundary] Component stack:", errorInfo.componentStack);
  }

  handleReload = () => {
    this.setState({ hasError: false, error: undefined });
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex min-h-screen items-center justify-center bg-[#020617] text-slate-50">
          <div className="max-w-md rounded-2xl border border-red-500/30 bg-slate-950/90 p-8 text-center shadow-2xl backdrop-blur">
            <div className="mb-4 text-5xl">⚠️</div>
            <h1 className="mb-2 text-xl font-bold text-slate-100">
              Something went wrong
            </h1>
            <p className="mb-6 text-sm text-slate-400">
              An unexpected error occurred. Please reload the application.
            </p>
            {this.state.error && (
              <pre className="mb-4 max-h-24 overflow-auto rounded-lg border border-slate-800 bg-slate-900 p-2 text-[10px] text-red-300/70">
                {this.state.error.message}
              </pre>
            )}
            <button
              onClick={this.handleReload}
              className="rounded-xl bg-gradient-to-r from-cyan-500 to-emerald-500 px-6 py-2.5 text-sm font-bold text-slate-950 shadow-lg hover:from-cyan-400 hover:to-emerald-400 transition"
            >
              Reload
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
