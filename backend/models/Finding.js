// backend/models/Finding.js
import mongoose from 'mongoose';

const findingSchema = new mongoose.Schema(
  {
    // Core finding fields (from AgentFinding)
    agent_name: {
      type: String,
      required: true,
      index: true,
    },
    threat_type: {
      type: String,
      required: true,
      index: true,
    },
    severity: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      required: true,
      index: true,
    },
    confidence: {
      type: Number,
      min: 0,
      max: 1,
      default: 0,
    },
    summary: {
      type: String,
      required: true,
    },
    actions: {
      type: [String],
      default: [],
    },
    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },

    // ---- NEW: endpoint identifier (source) ----
    source: {
      type: String,
      required: true,
      default: 'unknown',
      index: true,
    },

    // Timestamps
    timestamp: {
      type: Date,
      default: Date.now,
      index: true,
    },
  },
  {
    timestamps: true, // adds createdAt and updatedAt automatically
  }
);

// Compound index for efficient filtering by source + time
findingSchema.index({ source: 1, timestamp: -1 });

const Finding = mongoose.model('Finding', findingSchema);

export default Finding;