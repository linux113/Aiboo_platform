import mongoose from 'mongoose';

const agentCredentialSchema = new mongoose.Schema({
  organization: { type: mongoose.Schema.Types.ObjectId, ref: 'Organization', required: true, index: true },
  endpointId: { type: String, required: true, trim: true, maxlength: 160 },
  label: { type: String, default: '', trim: true, maxlength: 160 },
  keyId: { type: String, required: true, unique: true, index: true },
  secretHash: { type: String, required: true, select: false },
  status: { type: String, enum: ['active', 'revoked'], default: 'active', index: true },
  platform: { type: String, enum: ['windows', 'linux', 'darwin', 'unknown'], default: 'unknown' },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  lastSeenAt: { type: Date, default: null },
  lastSeenIp: { type: String, default: '' },
  revokedAt: { type: Date, default: null },
}, { timestamps: true });

agentCredentialSchema.index(
  { organization: 1, endpointId: 1 },
  { unique: true, partialFilterExpression: { status: 'active' } },
);

export default mongoose.model('AgentCredential', agentCredentialSchema);
