import mongoose from "mongoose";
import { ApiError } from "../utils/ApiError.js";

export const connectDB = async () => {
  try {
    const dbInstance = await mongoose.connect(process.env.MONGO_URL);
    console.log(dbInstance.connection.host,"--->", dbInstance.connection.port);
  } catch (error) {
    console.log("Database error::", error);
    throw new ApiError(500, error.message);
  }
};
