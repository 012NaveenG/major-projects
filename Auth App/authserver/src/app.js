import express, { urlencoded } from "express";
import cookieParser from "cookie-parser";
import cors from "cors";

const app = express();

app.use(cookieParser());
app.use(cors());
app.use(express.static("public"));
app.use(express.json());
app.use(express.urlencoded());

app.get("/", (_, res) => {
  return res.send("welcome to auth app backend");
});

import userRoutes from "./routes/user.routes.js";

app.use("/api/v1/users", userRoutes);

export { app };
