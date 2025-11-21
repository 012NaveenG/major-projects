import { Router } from "express";
import {
  loginUser,
  logoutUser,
  regenerateAccessToken,
  registerUser,
} from "../controllers/user.controllers.js";

const router = Router();

router.route("/register").post(registerUser);
router.route("/login").post(loginUser);
router.route("/access-token").post(regenerateAccessToken);
router.route("/logout").get(logoutUser);

export default router;
