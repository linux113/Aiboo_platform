import mongoose from 'mongoose';

const planSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true, lowercase: true, trim: true, enum: ['basic', 'business', 'enterprise'] },
  name: { type: String, required: true, trim: true, maxlength: 80 },
  description: { type: String, default: '', maxlength: 500 },
  currency: { type: String, default: 'INR', enum: ['INR'] },
  monthlyAmountPaise: { type: Number, min: 0, default: null },
  yearlyAmountPaise: { type: Number, min: 0, default: null },
  limits: {
    endpoints: { type: Number, min: 1, default: null },
    users: { type: Number, min: 1, default: null },
  },
  features: {
    windowsAgent: { type: Boolean, default: true },
    linuxAgent: { type: Boolean, default: true },
    reports: { type: Boolean, default: true },
    playbooks: { type: Boolean, default: false },
    responseActions: { type: Boolean, default: false },
    customIntegrations: { type: Boolean, default: false },
  },
  razorpayMonthlyPlanId: { type: String, default: '', trim: true },
  razorpayYearlyPlanId: { type: String, default: '', trim: true },
  customPricing: { type: Boolean, default: false },
  enabled: { type: Boolean, default: true, index: true },
  publicSignup: { type: Boolean, default: true },
}, { timestamps: true });

export default mongoose.model('Plan', planSchema);
