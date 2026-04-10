const mongoose = require("mongoose");

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
    select: false // 🔐 hidden by default
  },

  role: {
    type: String,
    enum: ["admin", "analyst", "user"],
    default: "user",
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

/* 🔐 Clean JSON response */
UserSchema.set("toJSON", {
  transform: (_, ret) => {
    delete ret.passwordHash;
    delete ret.__v;
    return ret;
  }
});

/* 🔥 Ensure email always lowercase */
UserSchema.pre("save", function (next) {
  if (this.email) {
    this.email = this.email.toLowerCase();
  }
  next();
});

module.exports = mongoose.model("User", UserSchema);