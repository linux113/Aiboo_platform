import mongoose from 'mongoose';

const cameraSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    streamUrl: { type: String, required: true }, // RTSP / IP / HTTP
    location: { type: String, default: '' },
    zone: { type: String, default: 'Default' },
    enabled: { type: Boolean, default: true },
    type: { type: String, enum: ['ip', 'rtsp', 'mobile', 'usb'], default: 'ip' },
    resolution: { type: String, default: '1080p' },
    fps: { type: Number, default: 30 },
    detectionEnabled: { type: Boolean, default: true },
    detectionTypes: {
      type: [String],
      default: ['person', 'vehicle', 'weapon', 'face', 'behavior'],
    },
    status: { type: String, enum: ['online', 'offline', 'error'], default: 'online' },
    lastSeen: { type: Date, default: Date.now },
    thumbnail: { type: String, default: '' },
    addedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  },
  { timestamps: true }
);

export default mongoose.model('Camera', cameraSchema);
