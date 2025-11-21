import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { AsyncHandler } from "../utils/AsyncHandler.js";
import bcrypt from "bcryptjs";
import jwt, { decode } from "jsonwebtoken";

const cookieOptions = {
  httpOnly: true,
  secure: true,
};

const generateAccessAndRefreshToken = async (userId, req) => {
  try {
    const user = await User.findById(userId);
    if (!user) throw new ApiError(404, "invlaid user");

    const AccessToken = await user.generateAccessToken();
    const RefreshToken = await user.generateRefreshToken();

    let ip =
      req.headers["x-forwarded-for"] || req.connection.remoteAddress || req.ip;

    if (ip === "::1" || ip === "0:0:0:0:0:0:0:1") {
      ip = "127.0.0.1"; // convert ipv6 localhost → ipv4 localhost
    }

    const userAgent = req.headers["user-agent"];

    user.refreshTokens.push({
      token: RefreshToken,
      userAgent,
      ip,
      expiresAt: new Date(Date.now() + 7 * 86400000),
      isValid: true,
    });

    await user.save({ validateBeforeSave: false });

    return { AccessToken, RefreshToken };
  } catch (error) {
    throw new ApiError(500, "Something went wrong while generating jwt token");
  }
};

const registerUser = AsyncHandler(async (req, res) => {
  const { name, email, username, password } = req.body;

  if (!name || !email || !username || !password)
    throw new ApiError(400, "All fields are required");

  const existingUser = await User.findOne({ email });
  if (existingUser) throw new ApiError(409, "User already registered");

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await User.create({
    name,
    email: email.toLowerCase().trim(),
    username,
    password: hashedPassword,
    authProvider: "local",
  });

  const returnUser = user.toObject();
  delete returnUser.password;

  return res
    .status(201)
    .json(new ApiResponse(201, returnUser, "User registered successfully"));
});

const loginUser = AsyncHandler(async (req, res) => {
  const { email, password, username } = req.body;
  if ((!email && !username) || !password)
    throw new ApiError(400, "Email/Username and password are required");

  const user = await User.findOne({
    $or: [{ email }, { username }],
  }).select("+password");

  if (!user) throw new ApiError(404, "Invalid credentials");
  if (user.authProvider !== "local")
    throw new ApiError(400, "Please login using Google/Github");

  const isPasswordCorrect = await bcrypt.compare(password, user.password);
  if (!isPasswordCorrect) throw new ApiError(401, "Invalid credentials");

  const { AccessToken, RefreshToken } = await generateAccessAndRefreshToken(
    user._id,
    req
  );

  const safeUser = user.toObject();
  delete safeUser.password;
  return res
    .status(200)
    .cookie("accessToken", AccessToken, cookieOptions)
    .cookie("refreshToken", RefreshToken, cookieOptions)
    .json(new ApiResponse(200, safeUser, "Login successfully"));
});

const regenerateAccessToken = AsyncHandler(async (req, res) => {
  const cookieRefreshToken = req.cookies?.refreshToken;

  if (!cookieRefreshToken) throw new ApiError(401, "Unauthorized");

  const decoded = jwt.verify(
    cookieRefreshToken,
    process.env.REFRESH_TOKEN_SECRET
  );

  if (!decoded) throw new ApiError(401, "Invalid token");

  const user = await User.findById(decoded.id).select("-password");
  if (!user) throw new ApiError(404, "User not found");

  const tokenIndex = user.refreshTokens.findIndex(
    (t) => t.token === cookieRefreshToken
  );

  if (tokenIndex === -1)
    throw new ApiError(403, "Refresh token not recognized");

  const existingToken = user.refreshTokens[tokenIndex];

  if (existingToken.expiresAt < new Date()) {
    throw new ApiError(401, "Refresh token expired, login again");
  }

  const newAccessToken = user.generateAccessToken();
  const newRefreshToken = user.generateRefreshToken();

  user.refreshTokens[tokenIndex] = {
    token: newRefreshToken,
    ip:
      req.ip || req.headers["x-forwarded-for"] || req.connection.remoteAddress,
    userAgent: req.headers["user-agent"],
    expiresAt: new Date(Date.now() + 7 * 86400000), // 7 days
    isValid: true,
  };

  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .cookie("accessToken", newAccessToken, cookieOptions)
    .cookie("refreshToken", newRefreshToken, cookieOptions)
    .json(
      new ApiResponse(
        200,
        { accessToken: newAccessToken, refreshToken: newRefreshToken },
        "Token rotated successfully"
      )
    );
});

const logoutUser = AsyncHandler(async (req, res) => {
  const refreshTokenCookie = req.cookies?.refreshToken;

  if (!refreshTokenCookie) {
    throw new ApiError(401, "invalid request");
  }

  const decodedToken = jwt.verify(
    refreshTokenCookie,
    process.env.REFRESH_TOKEN_SECRET
  );

  if (!decodedToken) throw new ApiError(401, "invalid token");

  const user = await User.findById(decodedToken.id).select("-password");

  if (!user) {
    throw new ApiError(401, "invalid request");
  }

  user.refreshTokens = user.refreshTokens.filter(
    (t) => t.token !== refreshTokenCookie
  );

  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .clearCookie("accessToken")
    .clearCookie("refreshToken")
    .json(new ApiResponse(200, {}, "Logout succesfully"));
});

export { registerUser, loginUser, logoutUser, regenerateAccessToken };
