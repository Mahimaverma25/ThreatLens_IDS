const mongoose = require("mongoose");
const {
  ROLE_ADMIN,
  ROLE_ANALYST,
  ROLE_VIEWER,
  normalizeRole,
} = require("../utils/roles");

const UserSchema = new mongoose.Schema({
  _org_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Organization",
    required: true,
    index: true
  },

  username: {
    type: String,
    trim: true,
    default: ""
  },

  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true,
    unique: true,
    index: true
  },

  passwordHash: {
    type: String,
    required: true,
    select: false
  },

  role: {
    type: String,
    enum: [ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER],
    default: ROLE_VIEWER,
    trim: true
  },

  lastLoginAt: { type: Date },
  lastLoginIp: { type: String, trim: true },

  createdAt: {
    type: Date,
    default: Date.now,
    immutable: true
  }
});

// Enforce a single admin per organization
UserSchema.index(
  { _org_id: 1, role: 1 },
  { unique: true, partialFilterExpression: { role: ROLE_ADMIN } }
);

UserSchema.set("toJSON", {
  transform: (_, ret) => {
    delete ret.passwordHash;
    delete ret.__v;
    return ret;
  }
});

UserSchema.pre("save", function (next) {
  if (this.email) {
    this.email = this.email.toLowerCase();
  }

  this.role = normalizeRole(this.role);

  next();
});

module.exports = mongoose.model("User", UserSchema);
