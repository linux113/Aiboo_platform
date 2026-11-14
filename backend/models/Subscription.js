import mongoose from 'mongoose';

const subscriptionSchema = new mongoose.Schema({
  organization: { type: mongoose.Schema.Types.ObjectId, ref: 'Organization', required: true, index: true },
  plan: { type: mongoose.Schema.Types.ObjectId, ref: 'Plan', required: true },
  planCode: { type: String, required: true, enum: ['basic', 'business', 'enterprise'] },
  billingCycle: { type: String, required: true, enum: ['monthly', 'yearly'] },
  provider: { type: String, enum: ['razorpay'], default: 'razorpay' },
  providerCustomerId: { type: String, default: '', index: true },
  providerSubscriptionId: { type: String, default: '', index: true },
  providerOrderId: { type: String, default: '', index: true },
  status: {
    type: String,
    enum: ['pending_payment', 'active', 'past_due', 'canceled', 'expired', 'suspended'],
    default: 'pending_payment',
    index: true,
  },
  currentPeriodStart: { type: Date, default: null },
  currentPeriodEnd: { type: Date, default: null, index: true },
  activatedAt: { type: Date, default: null },
  canceledAt: { type: Date, default: null },
  expiredAt: { type: Date, default: null },
  lastPaymentId: { type: String, default: '' },
  reminderDaysSent: { type: [Number], default: [] },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
}, { timestamps: true });

subscriptionSchema.index({ organization: 1, status: 1, currentPeriodEnd: 1 });
subscriptionSchema.index({ provider: 1, providerSubscriptionId: 1 }, { unique: true, sparse: true });

export default mongoose.model('Subscription', subscriptionSchema);
