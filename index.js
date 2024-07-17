const express = require("express");
const { MongoClient, ServerApiVersion } = require("mongodb");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const cors = require("cors");
require("dotenv").config();
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 5000;

app.use(
  cors({
    origin: ["http://localhost:5173", "http://localhost:5174"],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

// const uri = `mongodb://127.0.0.1:27017`;
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.7uejvxv.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();

    const easyPayUser = client.db("easyPay");
    const userCollection = easyPayUser.collection("users");

    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
    };

    // verify jwt
    const verifyJWT = async (req, res, next) => {
      const token = req?.cookies?.token;

      if (!token) {
        return res.status(401).send({ message: "unauthorized access" });
      }
      jwt.verify(token, process.env.ACCESS_TOKEN, (err, decoded) => {
        if (err) {
          return res.status(401).send({ message: "unauthorized access" });
        }
        req.decoded = decoded;
        next();
      });
    };

    // jwt
    app.post("/jwt", async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN, {
        expiresIn: "1h",
      });

      res.cookie("token", token, cookieOptions).send({ token, user });
    });

    // logout user
    app.post("/logout", async (req, res) => {
      res
        .clearCookie("token", { ...cookieOptions, maxAge: 0 })
        .send({ success: true });
    });

    // get jwt decoded
    app.post("/auth/verify", verifyJWT, (req, res) => {
      res.send({decoded: req.decoded});
    });

    // add new user
    app.post("/user/add", async (req, res) => {
      const data = req.body;

      const query = { email: data.email };
      const isUserExists = await userCollection.findOne(query);
      if (isUserExists) {
        return res.send({ isUserExists: true });
      }

      const pass = data.password;

      const salt = await bcrypt.genSalt(10);
      const hashPass = await bcrypt.hash(pass, salt);

      const userData = { ...data, password: hashPass };

      const result = await userCollection.insertOne(userData);
      res.send(result);
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Easy Pay server is running.");
});

app.listen(port, () => {
  console.log(`Easy Pay, server is running on port: ${port}`);
});