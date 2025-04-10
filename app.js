require("dotenv").config();
require("express-async-errors");
const express = require("express");
const YAML = require("yamljs");
const swaggerUI = require("swagger-ui-express");
const app = express();

// Connect db
// security

const rateLimiter = require("express-rate-limit");
const helmet = require("helmet");
const cors = require("cors");
const xss = require("xss-clean");
// Routers
const authRouter = require("./routes/auth");
const jobsRouter = require("./routes/jobs");
// error handler
const notFoundMiddleware = require("./middleware/not-found");
const errorHandlerMiddleware = require("./middleware/error-handler");
const { connect } = require("mongoose");
const auth = require("./middleware/authentication");
//////////////
const swaggerDocument = YAML.load("./swagger.yaml");
app.set("trust proxy", 1);
app.use(
  rateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
  })
);

app.use(express.json());

app.use(helmet());
app.use(cors());
app.use(xss());
app.use("/api-docs", swaggerUI.serve, swaggerUI.setup(swaggerDocument));
// extra packages

// routes

app.use("/api/v1/auth", authRouter);
app.use("/api/v1/jobs", auth, jobsRouter);
// app.use("/", [auth, (req, res) => res.send("hi")]);

app.use(notFoundMiddleware);
app.use(errorHandlerMiddleware);

const port = process.env.PORT || 3000;

const start = async () => {
  try {
    await connect(process.env.MONGO_URI);
    app.listen(port, () =>
      console.log(`Server is listening on port ${port}...`)
    );
  } catch (error) {
    console.log(error);
  }
};

start();
