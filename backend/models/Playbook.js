// backend/models/Playbook.js
// PseudoLock (Playbook). The shape is defined and validated in
// services/pseudolock.service.js; MongoDB stores the document as-is
// (strict: false) so the in-memory and MongoDB stores behave the same.
import mongoose from 'mongoose';

const schema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true },
    status: { type: String, index: true },
  },
  { strict: false, timestamps: true, minimize: false, collection: 'playbooks' }
);


export default mongoose.models.Playbook || mongoose.model('Playbook', schema);
