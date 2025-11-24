import { ActivityLog } from "../models/activityLog.model.js";

export const logActivity = async (data) => {
  try {
    await ActivityLog.create(data);
  } catch (error) {
    console.error("Activity Log Error:", error);
  }
};
