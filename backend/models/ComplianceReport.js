// backend/models/ComplianceReport.js
// Compliance report sent by an agent after each device check
// (ISO 27001:2022 Annex A + NIST CSF 2.0 mapping, see agent/gates/compliance_checks.py).
// Kept 90 days so the dashboard can show the trend.
import mongoose from 'mongoose';

const complianceSchema = new mongoose.Schema(
  {
    endpoint: { type: String, required: true, index: true },
    checkedAt: { type: Date, default: Date.now, index: true },
    score: { type: Number, default: null },
    counts: { type: mongoose.Schema.Types.Mixed, default: {} },
    frameworks: { type: mongoose.Schema.Types.Mixed, default: {} },
    checks: { type: [mongoose.Schema.Types.Mixed], default: [] },
    posture: { type: mongoose.Schema.Types.Mixed, default: {} },
  },
  { timestamps: true, minimize: false }
);

complianceSchema.index({ createdAt: 1 }, { expireAfterSeconds: 90 * 24 * 3600 });

export default mongoose.models.ComplianceReport || mongoose.model('ComplianceReport', complianceSchema);
