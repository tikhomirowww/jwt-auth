require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const router = require("./router");
const errorMiddleware = require("./middleware/error-middleware");

const PORT = process.env.PORT;
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({ credentials: true, origin: process.env.CLIENT_URL }));
app.use("/api", router);
app.use(errorMiddleware);

const start = async () => {
  try {
    await mongoose.connect(process.env.DB_URL);
    app.listen(PORT, () => console.log(`Server started on port - ${PORT}`));
  } catch (error) {
    console.log(error);
  }
};
start();
