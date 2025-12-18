const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
require("dotenv").config();

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET);
const admin = require("firebase-admin");

const serviceAccount = require("./civicpulse-website-firebase-adminsdk-fbsvc.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Firebase Token Verification Middleware
const verifyFBToken = async (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ message: "Unauthorized access" });

  try {
    const idToken = token.split(" ")[1];
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.decoded_email = decoded.email;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Unauthorized access" });
  }
};

// MongoDB Connection
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@sagorkumar.isv1anl.mongodb.net/?appName=SagorKumar`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// Utility: Generate Tracking ID
const generateTrackingId = () => {
  const prefix = "CP";
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const random = crypto.randomBytes(3).toString("hex").toUpperCase();
  return `${prefix}-${date}-${random}`;
};

// Start Server and DB
async function run() {
  try {
    await client.connect();
    const db = client.db("civic-pluse-db");
    const userCollection = db.collection("users");
    const issuesCollection = db.collection("issues");
    const trackingsCollection = db.collection("tracking");
    const paymentCollection = db.collection("payments");

    // Middleware: Check if user is blocked
    const checkBlockedUser = async (req, res, next) => {
      const email = req.decoded_email;
      const user = await userCollection.findOne({ email });
      if (!user) return res.status(404).json({ message: "User not found" });
      if (user.isBlocked)
        return res
          .status(403)
          .json({ message: "You are blocked. Action not allowed." });
      req.user = user;
      next();
    };

    // Utility: Log tracking
    const logTracking = async (trackingId, status, userId, role, message) => {
      const log = {
        trackingId,
        status,
        updatedBy: userId,
        role,
        message,
        createdAt: new Date(),
      };
      return await trackingsCollection.insertOne(log);
    };

    // ------------------- User APIs -------------------

    // Create user
    app.post("/users", async (req, res) => {
      const user = req.body;
      user.role = "citizen";
      user.isPremium = false;
      user.isBlocked = false;
      user.createdAt = new Date();

      const userExists = await userCollection.findOne({ email: user.email });
      if (userExists) return res.json({ message: "User exists" });

      const result = await userCollection.insertOne(user);
      res.json(result);
    });

    // Get users
    app.get("/users", verifyFBToken, async (req, res) => {
      const email = req.query.email;
      const query = {};
      if (email) {
        if (req.decoded_email !== email)
          return res.status(403).json({ message: "Forbidden access" });
        query.email = email;
      }
      const users = await userCollection.find(query).toArray();
      res.json(users);
    });

    // Get user role
    app.get("/users/:email/role", verifyFBToken, async (req, res) => {
      const email = req.params.email;
      const user = await userCollection.findOne({ email });
      res.json({ role: user?.role || "user" });
    });

    // --- NEW: Get user ID by email (for client-side use) ---
    app.get("/users/:email/id", verifyFBToken, async (req, res) => {
      try {
        const email = req.params.email;
        if (req.decoded_email !== email)
          return res.status(403).json({ message: "Forbidden access" });

        const user = await userCollection.findOne({ email });
        if (!user) return res.status(404).json({ message: "User not found" });

        res.json({
          id: user._id.toString(),
          name: user.displayName,
          email: user.email,
          isPremium: user.isPremium,
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
    });

    // Update user
    app.patch("/users/:id", verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        const { displayName, phone, photoURL } = req.body;
        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: {
            displayName,
            phone,
            ...(photoURL && { photoURL }),
            updatedAt: new Date(),
          },
        };
        const result = await userCollection.updateOne(filter, updateDoc);
        res.json(result);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
    });

    // ------------------- Issue APIs -------------------

    app.post("/issues", verifyFBToken, checkBlockedUser, async (req, res) => {
      const user = req.user;
      const { title, description, category, location, image } = req.body;

      // Free user limit
      if (!user.isPremium) {
        const count = await issuesCollection.countDocuments({
          createdBy: user._id.toString(),
        });
        if (count >= 3)
          return res.status(403).json({
            message: "Free user limit reached. Please subscribe.",
            subscribe: true,
          });
      }

      const trackingId = generateTrackingId();
      const issueData = {
        createdBy: user._id.toString(),
        name: user.displayName,
        email: user.email,
        title,
        description,
        category,
        location,
        image: image || null,
        status: "pending",
        priority: "normal",
        assignedStaff: null,
        upvotes: [],
        createdAt: new Date(),
        trackingId,
      };

      const result = await issuesCollection.insertOne(issueData);

      // Log tracking
      await logTracking(
        trackingId,
        "pending",
        user._id.toString(),
        user.role,
        `Issue reported by ${user.displayName}`
      );

      res.json({
        message: "Issue reported successfully",
        issueId: result.insertedId,
        trackingId,
      });
    });

    // Get count of issues by user
    app.get("/issues/count/:userId", verifyFBToken, async (req, res) => {
      try {
        const { userId } = req.params;
        const count = await issuesCollection.countDocuments({
          createdBy: userId,
        });
        res.json({ count });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
    });

    // ------------------- Payment APIs -------------------

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
        cancel_url: `${process.env.SITE_DOMAIN}/dashboard/payment-cancelled`,
      });

      res.send({ url: session.url });
    });

    app.patch("/payment-success", verifyFBToken, async (req, res) => {
      const { session_id } = req.query;
      const session = await stripe.checkout.sessions.retrieve(session_id);

      if (session.payment_status !== "paid")
        return res.status(400).json({ message: "Payment not completed" });

      const { email, userId } = session.metadata;

      const payment = {
        userId,
        email,
        amount: session.amount_total / 100,
        currency: session.currency,
        transactionId: session.id,
        paymentIntentId: session.payment_intent,
        status: "success",
        createdAt: new Date(),
      };

      await paymentCollection.insertOne(payment);
      await userCollection.updateOne({ email }, { $set: { isPremium: true } });

      // 🔹 Generate tracking for payment
      const trackingId = generateTrackingId();
      await trackingsCollection.insertOne({
        trackingId,
        status: "paid",
        updatedBy: userId,
        role: "citizen",
        message: `User ${email} upgraded to premium`,
        createdAt: new Date(),
      });

      res.json({ transactionId: session.id, trackingId });
    });

    await client.db("admin").command({ ping: 1 });
    console.log("Connected to MongoDB successfully!");
  } finally {
  }
}

run().catch(console.error);

app.get("/", (req, res) => res.send("civicpluse running...!"));

app.listen(port, () => console.log(`Server listening on port ${port}`));
