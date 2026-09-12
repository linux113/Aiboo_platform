import { useEffect, useState } from 'react';
import api, { authH } from '../utils/api';
import { cn } from '../utils/cn';

// Define the shape of an endpoint from the backend
interface Endpoint {
  source: string;
  lastSeen: string;
  active: boolean;
}

interface EndpointsListProps {
  onSelectEndpoint: (endpoint: string | null) => void;
  selectedEndpoint?: string | null;
}

export default function EndpointsList({ onSelectEndpoint, selectedEndpoint = null }: EndpointsListProps) {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchEndpoints = async () => {
      try {
        setLoading(true);
        const response = await api.get('/api/agent/endpoints', authH());
        // Response data is an array of { source, lastSeen, active }
        setEndpoints(response.data || []);
        setError(null);
      } catch (err: any) {
        console.error('Failed to fetch endpoints:', err);
        setError(err.response?.data?.message || err.message || 'Failed to load endpoints');
      } finally {
        setLoading(false);
      }
    };

    fetchEndpoints();

    // Refresh every 30 seconds to update status
    const interval = setInterval(fetchEndpoints, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading && endpoints.length === 0) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="flex flex-col items-center gap-2">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-cyan-400 border-t-transparent" />
          <span className="text-sm text-slate-500">Loading endpoints...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-4 text-center">
        <p className="text-sm text-red-400">{error}</p>
        <button
          onClick={() => window.location.reload()}
          className="mt-2 text-xs text-cyan-400 hover:underline"
        >
          Retry
        </button>
      </div>
    );
  }

  if (endpoints.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12">
        <span className="text-4xl mb-3">📡</span>
        <h3 className="text-sm font-medium text-slate-300">No endpoints connected</h3>
        <p className="text-xs text-slate-500 mt-1 max-w-sm text-center">
          No remote agents have reported findings yet. Ask friends to run the AiBoO Agent.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">
          Active Endpoints
          <span className="ml-2 rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-400">
            {endpoints.length}
          </span>
        </h2>
        <button
          onClick={() => onSelectEndpoint(null)}
          className="text-xs text-slate-500 hover:text-slate-300 transition"
        >
          Show All
        </button>
      </div>

      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {endpoints.map((ep) => (
          <button
            key={ep.source}
            onClick={() => onSelectEndpoint(ep.source)}
            className={`
              flex items-center justify-between rounded-lg border px-4 py-3 transition-all
              ${selectedEndpoint === ep.source
                ? 'border-cyan-500 bg-cyan-500/10 shadow-[0_0_20px_rgba(34,211,238,0.15)]'
                : 'border-slate-700/50 bg-slate-900/40 hover:border-slate-600 hover:bg-slate-800/40'
              }
            `}
          >
            <div className="flex items-center gap-3">
              <span className="text-lg">🖥️</span>
              <div className="text-left">
                <div className="text-sm font-medium text-slate-200">{ep.source}</div>
                <div className="text-[10px] text-slate-500">
                  {ep.active ? (
                    <span className="text-emerald-400 flex items-center gap-1">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                      Online
                    </span>
                  ) : (
                    <span className="text-red-400 flex items-center gap-1">
                      <span className="h-1.5 w-1.5 rounded-full bg-red-400" />
                      Offline
                    </span>
                  )}
                </div>
              </div>
            </div>
            {selectedEndpoint === ep.source && (
              <span className="h-2 w-2 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(34,211,238,0.6)]" />
            )}
          </button>
        ))}
      </div>
    </div>
  );
}