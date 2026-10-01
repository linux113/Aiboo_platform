// backend/models/Alert.js
// One row per security alert that needs a human: TriGate HOLD / BLOCK
// decisions, high/critical agent findings and correlated incidents.
// Stored in MongoDB so acknowledge / assign / close / notes survive restarts.
import mongoose from 'mongoose';

const noteSchema = new mongoose.Schema(
  { by: String, text: String, at: { type: Date, default: Date.now } },
  { _id: false }
);

const historySchema = new mongoose.Schema(
  {
    by: String,
    action: String, // created | acknowledged | assigned | closed | reopened | note | seen_again
    from: String,
    to: String,
    text: String,
    at: { type: Date, default: Date.now },
  },
  { _id: false }
);

const alertSchema = new mongoose.Schema(
  {
    alertId: { type: String, required: true, unique: true, index: true },
    kind: { type: String, enum: ['trigate', 'finding', 'incident'], required: true, index: true },
    source: { type: String, default: 'unknown', index: true }, // endpoint
    title: { type: String, default: '' },
    description: { type: String, default: '' },
    severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'medium', index: true },
    riskScore: { type: Number, default: 0 },
    verdict: { type: String, default: '' },
    pattern: { type: String, default: '', index: true },
    entity: { type: String, default: '' },
    subject: { type: String, default: '' },
    srcIp: { type: String, default: '' },

    status: { type: String, enum: ['open', 'acknowledged', 'closed'], default: 'open', index: true },
    assignee: { type: String, default: '' },
    closeReason: {
      type: String,
      enum: ['', 'resolved', 'false_positive', 'duplicate', 'accepted_risk'],
      default: '',
    },
    notes: { type: [noteSchema], default: [] },
    history: { type: [historySchema], default: [] },

    occurrences: { type: Number, default: 1 },
    firstSeen: { type: Date, default: Date.now, index: true },
    lastSeen: { type: Date, default: Date.now },
    acknowledgedAt: Date,
    acknowledgedBy: String,
    closedAt: Date,
    closedBy: String,

    data: { type: mongoose.Schema.Types.Mixed, default: {} },
  },
  { timestamps: true, minimize: false }
);

alertSchema.index({ status: 1, severity: 1, lastSeen: -1 });

export default mongoose.models.Alert || mongoose.model('Alert', alertSchema);
