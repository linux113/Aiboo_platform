import mongoose from 'mongoose';

const identityRiskSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    riskScore: { type: Number, min: 0, max: 100 },
    anomalyScore: { type: Number, min: 0, max: 100 },
    lastSeen: { type: Date },
    accessLevel: { type: String },
    flagged: { type: Boolean, default: false },
  },
  { timestamps: true }
);

export default mongoose.model('IdentityRisk', identityRiskSchema);