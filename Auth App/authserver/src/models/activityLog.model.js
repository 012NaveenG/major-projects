import mongoose from "mongoose";

const activitySchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    action: { type: String, required: true },
    ip: String,
    userAgent: String,
    method: String,
    url: String,
    status: { type: String, enum: ["success", "failed"] },
  },
  { timestamps: true }
);

export const ActivityLog = mongoose.model("ActivityLog", activitySchema);
