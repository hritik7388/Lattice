import express from "express";
import Mongoose from "mongoose";
import * as http from "http";
import * as path from "path";
import cors from "cors";
import morgan from "morgan";
import socket from "socket.io";
import swaggerUi from "swagger-ui-express";
import swaggerJSDoc from "swagger-jsdoc";
import apiErrorHandler from "../helper/apiErrorHandler"; 
import dotenv from "dotenv";
dotenv.config();
const app = new express();
const server = http.createServer(app);
const root = path.normalize(`${__dirname}/../..`);
class ExpressServer {
  constructor() {
    app.use(express.json({ limit: "1000mb" }));

    app.use(express.urlencoded({ extended: true, limit: "1000mb" }));

    app.use(morgan("dev"));

    app.use(
      cors({
        allowedHeaders: ["Content-Type", "token", "authorization"],
        exposedHeaders: ["token", "authorization"],
        origin: "*",
        methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
        preflightContinue: false,
      })
    );
  }
  router(routes) {
    routes(app);
    return this;
  }

  configureSwagger(swaggerDefinition) {
    const options = {
      swaggerDefinition,
      apis: [
        path.resolve(`${root}/server/api/v1/controllers/**/*.js`,),
        path.resolve(`${root}/api.yaml`),
      ],
       
    };

    app.use(
      "/api-docs",
      swaggerUi.serve,
      swaggerUi.setup(swaggerJSDoc(options))
    );
    return this;
  }

  handleError() {
    app.use(apiErrorHandler);

    return this;
  }

  configureDb(dbUrl) {
    return new Promise((resolve, reject) => {
      Mongoose.connect(
        dbUrl,
        {
          useNewUrlParser: true,
          useUnifiedTopology: true,
          // supressReservedKeysWarning: true
        },
        (err) => {
          if (err) {
            console.log(`Error in mongodb connection 🌍 ${err.message}`);
            return reject(err);
          }
          console.log("Mongodb connection established");
          return resolve(this);
        }
      );
    });
  }

  listen(port) {
    server.listen(port, () => {
      console.log(
        `secure app is listening 🌍 @port ${port}`,
        new Date().toLocaleString()
      );
    });
    return app;
  }
  
}

export default ExpressServer;
