import { Router } from "express";
import {
  forgotPassword,
  loginUser,
  logoutUser,
  regenerateAccessToken,
  registerUser,
  resetPassword,
} from "../controllers/user.controllers.js";

import { verifyJWT, authorizeRoles } from "../middlewares/auth.middleware.js";
import rateLimit from "express-rate-limit";
import { activityLogMiddleware } from "../middlewares/activityLog.middleware.js";

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 15 min me 10 requests allowed
  message: "Too many login attempts. Try again later.",
  standardHeaders: true,
  legacyHeaders: false,
});

const router = Router();

router
  .route("/register")
  .post(registerUser, activityLogMiddleware("user_register"));
router
  .route("/login")
  .post(loginLimiter, loginUser, activityLogMiddleware("user_login"));
router
  .route("/access-token")
  .post(
    activityLogMiddleware("user_access_token_regenerate"),
    regenerateAccessToken
  );
router
  .route("/logout")
  .get(activityLogMiddleware("user_logout"), verifyJWT, logoutUser);

router.route("/forgot-password").post(forgotPassword);
router.route("/reset-password/:token").post(resetPassword);

export default router;
