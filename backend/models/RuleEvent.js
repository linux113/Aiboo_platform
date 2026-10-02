// backend/models/RuleEvent.js
// PseudoLock response rules (RuleEvent). Shape defined / validated in
// services/responseRules.service.js; stored as-is (strict: false) so the
// in-memory and MongoDB stores behave the same.
import mongoose from 'mongoose';

const schema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true },
    status: { type: String, index: true },
  },
  { strict: false, timestamps: true, minimize: false, collection: 'ruleevents' }
);

// history is kept 90 days
schema.index({ createdAt: 1 }, { expireAfterSeconds: 90 * 24 * 3600 });

export default mongoose.models.RuleEvent || mongoose.model('RuleEvent', schema);
