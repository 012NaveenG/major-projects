import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken";

const refreshTokenSchema = new Schema(
  {
    token: {
      type: String,
    },
    ip: String,
    userAgent: String,
    expiresAt: {
      type: Date,
      default: function () {
        return new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
      },
    },
    isValid: {
      type: Boolean,
      default: true,
    },
  },
  { timestamps: true }
);

const userSchema = new Schema(
  {
    username: {
      type: String,
      lowercase: true,
      trim: true,
      index: true,
      required: true,
      unique: true,
    },
    name: String,

    email: {
      type: String,
      unique: true,
      trim: true,
    },

    password: {
      type: String,
      select: false,
      default: null,
    },

    avatar: {
      type: String,
      default:
        "https://www.pngall.com/wp-content/uploads/5/Profile-Avatar-PNG.png",
    },

    authProvider: {
      type: String,
      enum: ["local", "google", "github"],
      default: "local",
    },

    googleId: {
      type: String,
      default: null,
    },

    isEmailVerified: {
      type: Boolean,
      default: false,
    },

    refreshTokens: [refreshTokenSchema],
    resetPasswordToken: {
      type: String,
    },
    resetPasswordExpiry: {
      type: Date,
    },
  },
  { timestamps: true }
);

userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      id: this._id,
      email: this.email,
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRES,
    }
  );
};

userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    {
      id: this._id,
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRES,
    }
  );
};

export const User = mongoose.model("User", userSchema);
