import mongoose from 'mongoose';

// Razorpay may retry webhooks. Persist each provider event id so the same
// payment cannot activate a subscription twice or replay status transitions.
const billingWebhookEventSchema = new mongoose.Schema({
  provider: { type: String, required: true, enum: ['razorpay'] },
  providerEventId: { type: String, required: true, trim: true },
  eventType: { type: String, required: true, trim: true },
  processed: { type: Boolean, default: false, index: true },
  receivedAt: { type: Date, default: Date.now },
  processedAt: { type: Date, default: null },
  failureReason: { type: String, default: '', maxlength: 500 },
}, { timestamps: true });

billingWebhookEventSchema.index({ provider: 1, providerEventId: 1 }, { unique: true });

export default mongoose.model('BillingWebhookEvent', billingWebhookEventSchema);
