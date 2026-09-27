import mongoose from 'mongoose';

const responseActionSchema = new mongoose.Schema(
  {
    type: { type: String, enum: ['isolate', 'block', 'lock', 'escalate', 'auto'], required: true },
    target: { type: String, required: true },
    triggeredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    timestamp: { type: Date, default: Date.now },
    status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  },
  { timestamps: true }
);

export default mongoose.model('ResponseAction', responseActionSchema);
