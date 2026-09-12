// src/models/Threat.js
import mongoose from 'mongoose';

const threatSchema = new mongoose.Schema(
  {
    severity: { type: String, enum: ['critical', 'high', 'medium', 'low'], required: true },
    title: { type: String, required: true },
    description: { type: String },
    asset: { type: String },
    source: { type: String, enum: ['firewall', 'camera', 'va-scan'], required: true },
    status: { type: String, enum: ['open', 'investigating', 'resolved'], default: 'open' },
    timestamp: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

export default mongoose.model('Threat', threatSchema);