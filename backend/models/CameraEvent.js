import mongoose from 'mongoose';

// @deprecated This model is available but currently unused.
// It may be removed in a future release if no consumers adopt it.
// Tracked for potential re-use with camera event logging features.

const cameraEventSchema = new mongoose.Schema(
  {
    cameraId: { type: String, required: true },
    location: { type: String },
    eventType: { type: String, enum: ['person', 'breach', 'motion'], required: true },
    confidence: { type: Number, min: 0, max: 100 },
    snapshotUrl: { type: String },
    timestamp: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

export default mongoose.model('CameraEvent', cameraEventSchema);