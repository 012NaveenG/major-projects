import { logActivity } from "../utils/activityLog.js";

export const activityLogMiddleware = (action) => {
  return (req, res, next) => {
    res.on("finish", () => {
      logActivity({
        user: req.user?._id || null,
        action,
        ip: req.ip,
        userAgent: req.headers["user-agent"],
        method: req.method,
        url: req.originalUrl,
        status: res.statusCode < 400 ? "success" : "failed",
      });
    });
    next();
  };
};
