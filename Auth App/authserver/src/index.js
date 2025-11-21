import dotenv from "dotenv";

import { app } from "./app.js";
import { connectDB } from "./DB/_db.js";
dotenv.config({ path: "./.env" });
const PORT = process.env.PORT || 12345;

connectDB()
  .then(() => {
    app.listen(PORT, () =>
      console.log(`Server is listening at http://localhost:${PORT}`)
    );
  })
  .catch((err) => console.log("MONGO_DB Connection Failed!!", err));
