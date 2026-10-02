// backend/models/ResponseRule.js
// PseudoLock response rules (ResponseRule). Shape defined / validated in
// services/responseRules.service.js; stored as-is (strict: false) so the
// in-memory and MongoDB stores behave the same.
import mongoose from 'mongoose';

const schema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true },
    status: { type: String, index: true },
  },
  { strict: false, timestamps: true, minimize: false, collection: 'responserules' }
);


export default mongoose.models.ResponseRule || mongoose.model('ResponseRule', schema);
