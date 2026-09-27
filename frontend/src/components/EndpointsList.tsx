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

  const fetchEndpoints = async () => {
    try {
      setLoading(true);
      const response = await api.get('/api/agent/endpoints', authH());
      setEndpoints(response.data || []);
      setError(null);
    } catch (err: any) {
      console.error('Failed to fetch endpoints:', err);
      setError(err.response?.data?.message || err.message || 'Failed to load endpoints');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEndpoints();

    // Refresh every 15 seconds to keep active/offline status accurate
    const interval = setInterval(fetchEndpoints, 15000);
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
          onClick={fetchEndpoints}
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

  // Sort: active endpoints first, then by last seen (most recent first)
  const sortedEndpoints = [...endpoints].sort((a, b) => {
    if (a.active !== b.active) return a.active ? -1 : 1;
    return new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime();
  });

  const activeCount = endpoints.filter((e) => e.active).length;
  const offlineCount = endpoints.length - activeCount;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2 flex-wrap">
          Registered Endpoints
          <span className="rounded-full bg-slate-800 px-2 py-0.5 text-xs text-slate-400">
            {endpoints.length} total
          </span>
          {activeCount > 0 && (
            <span className="rounded-full bg-emerald-500/20 px-2 py-0.5 text-xs text-emerald-300">
              {activeCount} online
            </span>
          )}
          {offlineCount > 0 && (
            <span className="rounded-full bg-red-500/20 px-2 py-0.5 text-xs text-red-300">
              {offlineCount} offline
            </span>
          )}
        </h2>
        <button
          onClick={() => onSelectEndpoint(null)}
          className="text-xs text-slate-500 hover:text-slate-300 transition"
        >
          Show All
        </button>
      </div>

      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {sortedEndpoints.map((ep) => {
          const isSelected = selectedEndpoint === ep.source;
          const lastSeenText = ep.lastSeen
            ? new Date(ep.lastSeen).toLocaleTimeString()
            : 'Never';

          return (
            <button
              key={ep.source}
              onClick={() => onSelectEndpoint(ep.source)}
              className={cn(
                'flex items-center justify-between rounded-lg border px-4 py-3 transition-all text-left',
                isSelected
                  ? 'border-cyan-500 bg-cyan-500/10 shadow-[0_0_20px_rgba(34,211,238,0.15)]'
                  : 'border-slate-700/50 bg-slate-900/40 hover:border-slate-600 hover:bg-slate-800/40'
              )}
            >
              <div className="flex items-center gap-3 min-w-0">
                <span className="text-lg flex-shrink-0">🖥️</span>
                <div className="text-left min-w-0">
                  <div className="text-sm font-medium text-slate-200 truncate">
                    {ep.source}
                  </div>
                  <div className="text-[10px] text-slate-500">
                    {ep.active ? (
                      <span className="text-emerald-400 flex items-center gap-1">
                        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                        Online · {lastSeenText}
                      </span>
                    ) : (
                      <span className="text-red-400 flex items-center gap-1">
                        <span className="h-1.5 w-1.5 rounded-full bg-red-400" />
                        Offline · last seen {lastSeenText}
                      </span>
                    )}
                  </div>
                </div>
              </div>
              <span
                title={ep.active ? 'Online' : 'Offline'}
                className={cn(
                  'h-2.5 w-2.5 rounded-full flex-shrink-0 ml-2',
                  ep.active
                    ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.6)]'
                    : 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.6)]'
                )}
              />
            </button>
          );
        })}
      </div>
    </div>
  );
}