import mongoose from 'mongoose';

const detectionSchema = new mongoose.Schema(
  {
    cameraId: { type: mongoose.Schema.Types.Mixed, required: true }, // ObjectId for DB cameras, string for CV-only (webcam)
    cameraName: { type: String },
    location: { type: String },
    type: {
      type: String,
      enum: ['person', 'vehicle', 'weapon_gun', 'weapon_knife', 'face_known', 'face_unknown', 'face_watchlist', 'crowd', 'behavior_anomaly', 'bag', 'breach', 'device'],
      required: true,
    },
    severity: { type: String, enum: ['critical', 'high', 'medium', 'low'], default: 'low' },
    confidence: { type: Number, min: 0, max: 100, default: 0 },
    boundingBox: {
      x: Number, y: Number, width: Number, height: Number,
    },
    label: { type: String },
    snapshotUrl: { type: String },
    metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
    acknowledged: { type: Boolean, default: false },
    escalated: { type: Boolean, default: false },
    timestamp: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

export default mongoose.model('Detection', detectionSchema);
