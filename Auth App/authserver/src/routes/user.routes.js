import { Router } from "express";
import {
  forgotPassword,
  loginUser,
  logoutUser,
  regenerateAccessToken,
  registerUser,
  resetPassword,
} from "../controllers/user.controllers.js";

const router = Router();

router.route("/register").post(registerUser);
router.route("/login").post(loginUser);
router.route("/access-token").post(regenerateAccessToken);
router.route("/logout").get(logoutUser);

router.route("/forgot-password").post(forgotPassword);
router.route("/reset-password/:token").post(resetPassword);

export default router;
