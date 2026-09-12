import mongoose from 'mongoose';

const assetSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    ip: { type: String },
    zone: { type: String },
    riskScore: { type: Number, min: 0, max: 100 },
    lastScan: { type: Date },
    vulnerabilities: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Vulnerability' }],
  },
  { timestamps: true }
);

export default mongoose.model('Asset', assetSchema);