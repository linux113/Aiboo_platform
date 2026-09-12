import mongoose from 'mongoose';

/**
 * AgentEvent — persistent store for agent-pushed data.
 *
 * The in-memory store in routes/agent.routes.js is fast but volatile;
 * every agent push is ALSO mirrored here (fire-and-forget) so findings,
 * correlated alerts, gate decisions, pseudo-locks, response actions and
 * endpoint heartbeats survive backend restarts. Reads hydrate from this
 * collection once after boot.
 *
 * kinds: finding | correlated | gate | lock | response | endpoint
 * key:   dedupe/upsert key (finding id, alert_id, event_id:gate, lock_id, source…)
 */
const agentEventSchema = new mongoose.Schema(
  {
    kind: { type: String, required: true, index: true },
    key: { type: String, required: true },
    data: { type: mongoose.Schema.Types.Mixed, required: true },
  },
  { timestamps: true }
);

agentEventSchema.index({ kind: 1, key: 1 }, { unique: true });
agentEventSchema.index({ kind: 1, createdAt: -1 });

// Auto-purge after 30 days so the collection doesn't grow forever.
agentEventSchema.index({ createdAt: 1 }, { expireAfterSeconds: 60 * 60 * 24 * 30 });

export default mongoose.model('AgentEvent', agentEventSchema);
