const express = require("express");
const cors = require("cors");
const app = express();
require("dotenv").config();

const { MongoClient, ServerApiVersion } = require("mongodb");
const stripe = require('stripe')(process.env.STRIPE_SECRET);
const port = process.env.PORT || 3000;

const admin = require("firebase-admin");

const serviceAccount = require("./civicpulse-website-firebase-adminsdk-fbsvc.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

//middleWare
app.use(express.json());
app.use(cors());
const verifyFBToken = async (req, res, next) => {
  console.log("headers in the middleware", req.headers?.authorization);
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).send({ message: "unauthorized access" });
  }
  try {
    const idToken = token.split(" ")[1];
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.decoded_email = decoded.email;

    
    next();
  } catch (err) {
    return res.status(401).send({ message: "unauthorized access" });
  }
};

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@sagorkumar.isv1anl.mongodb.net/?appName=SagorKumar`;

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
    const db = client.db("civic-pluse-db");
    const userCollection = db.collection("users");
    const IssuesCollection = db.collection("issues");
    const trackingsCollection = db.collection("tracking");
    const paymentCollection = db.collection("payments");

    app.post("/users", async (req, res) => {
      const user = req.body;
      user.role = "citizen";
      user.isPremium = false;
      user.isBlocked = false;
      user.createdAt = new Date();
      const email = user.email;
      const userExists = await userCollection.findOne({ email });
      if (userExists) {
        return res.send({ message: "user exists" });
      }
      const result = await userCollection.insertOne(user);
      res.send(result);
    });

    // get user api

    app.get("/users", verifyFBToken, async (req, res) => {
      const email = req.query.email;
      const query = {};
      if (email) {
        query.email = email;
        if (req.decoded_email !== email) {
          return res.status(403).send({ message: "forbidden access" });
        }
      }
      const result = await userCollection.find(query).toArray();
      res.send(result);
    });

    app.post("/issues", verifyFBToken, async (req, res) => {
      const issue = req.body;

      issue.status = "pending";
      issue.priority = "normal";
      issue.upvotes = [];
      issue.assignedStaff = null;
      issue.createdAt = new Date();

      const result = await IssuesCollection.insertOne(issue);
      res.send(result);
    });

    //role Api
    app.get("/users/:email/role", verifyFBToken, async (req, res) => {
      const email = req.params.email;
      const query = { email };
      const user = await userCollection.findOne(query);
      res.send({ role: user?.role || "user" });
    });


    //payment related apis

  app.post("/payment-checkout-session", verifyFBToken, async (req, res) => {
  const { Name, userId, email, price } = req.body;

  const session = await stripe.checkout.sessions.create({
    payment_method_types: ["card"],
    line_items: [
      {
        price_data: {
          currency: "bdt",
          unit_amount: price * 100,
          product_data: { name: `Premium for ${Name}` },
        },
        quantity: 1,
      },
    ],
    mode: "payment",
    metadata: { userId, email },
    success_url: `${process.env.SITE_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${process.env.SITE_DOMAIN}/dashboard`,
  });

  res.send({ url: session.url });
});

    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("civicpluse running...!");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
