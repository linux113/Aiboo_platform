// backend/models/Approval.js
// PseudoLock (Approval). The shape is defined and validated in
// services/pseudolock.service.js; MongoDB stores the document as-is
// (strict: false) so the in-memory and MongoDB stores behave the same.
import mongoose from 'mongoose';

const schema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true },
    status: { type: String, index: true },
  },
  { strict: false, timestamps: true, minimize: false, collection: 'approvals' }
);

// history is kept 180 days
schema.index({ createdAt: 1 }, { expireAfterSeconds: 180 * 24 * 3600 });

export default mongoose.models.Approval || mongoose.model('Approval', schema);
