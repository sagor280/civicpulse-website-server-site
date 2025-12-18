const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const app = express();
require("dotenv").config();

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET);
const port = process.env.PORT || 3000;

const admin = require("firebase-admin");
const serviceAccount = require("./civicpulse-website-firebase-adminsdk-fbsvc.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Middleware
app.use(express.json());
app.use(cors());

const verifyFBToken = async (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).send({ message: "unauthorized access" });

  try {
    const idToken = token.split(" ")[1];
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.decoded_email = decoded.email;
    next();
  } catch (err) {
    return res.status(401).send({ message: "unauthorized access" });
  }
};

// MongoDB connection
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@sagorkumar.isv1anl.mongodb.net/?appName=SagorKumar`;
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

// 🔹 Tracking ID generator
function generateTrackingId() {
  const prefix = "CP"; // CivicPulse prefix
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const random = crypto.randomBytes(3).toString("hex").toUpperCase();
  return `${prefix}-${date}-${random}`;
}

async function run() {
  try {
    await client.connect();
    const db = client.db("civic-pluse-db");
    const userCollection = db.collection("users");
    const IssuesCollection = db.collection("issues");
    const trackingsCollection = db.collection("tracking");
    const paymentCollection = db.collection("payments");

    // Create user
    app.post("/users", async (req, res) => {
      const user = req.body;
      user.role = "citizen";
      user.isPremium = false;
      user.isBlocked = false;
      user.createdAt = new Date();
      const email = user.email;
      const userExists = await userCollection.findOne({ email });
      if (userExists) return res.send({ message: "user exists" });

      const result = await userCollection.insertOne(user);
      res.send(result);
    });

    // Get users
    app.get("/users", verifyFBToken, async (req, res) => {
      const email = req.query.email;
      const query = {};
      if (email) {
        query.email = email;
        if (req.decoded_email !== email) return res.status(403).send({ message: "forbidden access" });
      }
      const result = await userCollection.find(query).toArray();
      res.send(result);
    });

    // Update user
    app.patch("/users/:id", verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        const { displayName, phone, photoURL } = req.body;
        const filter = { _id: new ObjectId(id) };
        const updateDoc = { $set: { displayName, phone, ...(photoURL && { photoURL }), updatedAt: new Date() } };
        const result = await userCollection.updateOne(filter, updateDoc);
        res.send(result);
      } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Server error" });
      }
    });

    // Role API
    app.get("/users/:email/role", verifyFBToken, async (req, res) => {
      const email = req.params.email;
      const user = await userCollection.findOne({ email });
      res.send({ role: user?.role || "user" });
    });

    // Payment checkout session
    app.post("/payment-checkout-session", verifyFBToken, async (req, res) => {
      const { Name, userId, email, price } = req.body;

      const session = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        line_items: [
          { price_data: { currency: "bdt", unit_amount: price * 100, product_data: { name: `Premium for ${Name}` } }, quantity: 1 },
        ],
        mode: "payment",
        metadata: { userId, email },
        success_url: `${process.env.SITE_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.SITE_DOMAIN}/dashboard/payment-cancelled`,
      });

      res.send({ url: session.url });
    });

    // Payment success with trackingId
    app.patch("/payment-success", verifyFBToken, async (req, res) => {
      const { session_id } = req.query;
      const session = await stripe.checkout.sessions.retrieve(session_id);

      if (session.payment_status !== "paid") return res.status(400).send({ message: "Payment not completed" });

      const email = session.metadata.email;
      const userId = session.metadata.userId;

      const trackingId = generateTrackingId();

      // Save payment
      const payment = {
        userId,
        email,
        amount: session.amount_total / 100,
        currency: session.currency,
        transactionId: session.id,
        paymentIntentId: session.payment_intent,
        status: "success",
        trackingId,
        createdAt: new Date(),
      };
      await paymentCollection.insertOne(payment);

      // Update user to premium
      await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { isPremium: true } });

      res.send({ transactionId: session.id, trackingId });
    });

    await client.db("admin").command({ ping: 1 });
    console.log("MongoDB connected successfully!");
  } finally {
    
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("civicpluse running...!");
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
