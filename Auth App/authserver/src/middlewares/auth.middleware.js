import { User } from "../models/user.model.js";
import jwt from "jsonwebtoken";
import { AsyncHandler } from "../utils/AsyncHandler.js";
import { ApiError } from "../utils/ApiError.js";

export const verifyJWT = AsyncHandler(async (req, __dirname, next) => {
  const token =
    req.cookies?.accessToken ||
    req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    throw new ApiError(401, "Unauthorized request");
  }

  const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
  if (!decodedToken) throw new ApiError(401, "invalid token");

  const user = await User.findById(decodedToken?.id).select("-password ");
  if (!user) {
    throw new ApiError(401, "Invalid Access Token");
  }

  req.user = user;
  next();
});

export const authorizeRoles = (...allowedRoles) => {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return next(
        new ApiError(403, "You are not authorized to access this resource")
      );
    }

    next();
  };
};
