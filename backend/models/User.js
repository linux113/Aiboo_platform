import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['super_admin', 'admin', 'analyst', 'viewer'], default: 'viewer' },
    // A company-scoped user belongs to exactly one organization. Null is kept
    // temporarily for pre-migration accounts; tenant-aware routes must reject
    // or safely map such accounts before self-service tenants are enabled.
    organization: { type: mongoose.Schema.Types.ObjectId, ref: 'Organization', default: null, index: true },
    // Platform-wide access is reserved for a separately bootstrapped
    // super_admin. Do not assign it until all company routes are tenant-scoped.
    // Existing unassigned accounts stay in the internal legacy workspace during migration.
    // An admin can switch an account off (Settings -> Users) without deleting
    // it, so history keeps pointing at a real person. Missing = active, so
    // accounts created before this field existed keep working.
    active: { type: Boolean, default: true },
    lastLogin: { type: Date },
  },
  { timestamps: true }
);

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.index({ role: 1 }, { unique: true, partialFilterExpression: { role: 'super_admin' } });

userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

export default mongoose.model('User', userSchema);