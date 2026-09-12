import mongoose from 'mongoose';

const settingSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    section: { type: String, required: true, enum: ['profile', 'alerts', 'voice', 'system', 'security'] },
    data: { type: mongoose.Schema.Types.Mixed, default: {} },
  },
  { timestamps: true }
);

settingSchema.index({ userId: 1, section: 1 }, { unique: true });

export default mongoose.model('Setting', settingSchema);
