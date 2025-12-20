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

    // ------------------- Admin Middleware -------------------
    const verifyAdmin = async (req, res, next) => {
      try {
        const email = req.decoded_email;
        const user = await userCollection.findOne({ email });
        if (!user || user.role !== "admin") {
          return res.status(403).json({ message: "Admin access required" });
        }
        next();
      } catch (err) {
        console.error("verifyAdmin Error:", err);
        res.status(500).json({ message: "Server error" });
      }
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

    // --- NEW: Get user ID by email
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

    // Get issues of a logged-in user
    app.get("/myissues", verifyFBToken, checkBlockedUser, async (req, res) => {
      try {
        const email = req.query.email;
        if (!email) return res.status(400).json({ message: "Email required" });

        const issues = await issuesCollection.find({ email }).toArray();
        res.json(issues);
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

    // ------------------- All Issues (Admin) -------------------
    app.get("/issues/all", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const issues = await issuesCollection
          .find()
          .sort({ isBoosted: -1 })
          .toArray();
        res.json(issues);
      } catch (err) {
        console.error("Get All Issues Error:", err);
        res.status(500).json({ message: "Failed to fetch issues" });
      }
    });

    app.get("/users/staff", verifyFBToken, verifyAdmin, async (req, res) => {
      const staffs = await userCollection.find({ role: "staff" }).toArray();
      res.send(staffs);
    });

    // ------------------- Reject Issue (Admin) -------------------
    app.patch(
      "/issues/reject/:id",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const { id } = req.params;

          // Check issue exists
          const issue = await issuesCollection.findOne({
            _id: new ObjectId(id),
          });
          if (!issue) {
            return res
              .status(404)
              .json({ success: false, message: "Issue not found" });
          }

          if (issue.status !== "pending") {
            return res.status(400).json({
              success: false,
              message: "Only pending issues can be rejected",
            });
          }

          // Update status
          const result = await issuesCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { status: "rejected", rejectedAt: new Date() } }
          );

          // Tracking log
          await logTracking(
            issue.trackingId || id,
            "rejected",
            "admin",
            "Issue rejected by admin"
          );

          res.json({
            success: true,
            message: "Issue rejected successfully",
            result,
          });
        } catch (error) {
          console.error("Reject Issue Error:", error);
          res
            .status(500)
            .json({ success: false, message: "Internal Server Error" });
        }
      }
    );

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

    //issue delete
    app.delete(
      "/issues/:id",
      verifyFBToken,
      checkBlockedUser,
      async (req, res) => {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const cursor = await issuesCollection.deleteOne(query);
        res.send(cursor);
      }
    );
    //issue update api

    app.patch(
      "/issues/:id",
      verifyFBToken,
      checkBlockedUser,
      async (req, res) => {
        try {
          const id = req.params.id;
          const updateData = req.body;
          const filter = { _id: new ObjectId(id) };
          const updateDoc = {
            $set: {
              title: updateData.title,
              catagory: updateData.category,
              description: updateData.description,
              photoURL: updateData.photoURL,
              location: updateData.location,
              updatedAt: new Date(),
            },
          };

          const result = await issuesCollection.updateOne(filter, updateDoc);

          res.send(result);
        } catch (error) {
          console.log("Update Issue Error:", error);
          res.status(500).send({ message: "Internal Server Error" });
        }
      }
    );

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

    // Create boost session
    app.post(
      "/payment-checkout-session/boosting",
      verifyFBToken,
      checkBlockedUser,
      async (req, res) => {
        const { Issueid, Issuetitle, price, createrEmail, trackingId } =
          req.body;
        const amount = parseInt(price) * 100;

        const session = await stripe.checkout.sessions.create({
          payment_method_types: ["card"],
          line_items: [
            {
              price_data: {
                currency: "bdt",
                unit_amount: amount,
                product_data: { name: `Boost Issue: ${Issuetitle}` },
              },
              quantity: 1,
            },
          ],
          mode: "payment",
          metadata: { Issueid, Issuetitle, trackingId },
          customer_email: createrEmail,
          success_url: `${process.env.SITE_DOMAIN}/dashboard/payment-success-boosting?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${process.env.SITE_DOMAIN}/dashboard/payment-cancelled-boosting`,
        });
        res.json({ url: session.url });
      }
    );

    // Boosting payment success
    app.patch("/payment-success-boosting", async (req, res) => {
      try {
        const sessionId = req.query.session_id;
        if (!sessionId)
          return res.status(400).json({ message: "Session ID missing" });

        const session = await stripe.checkout.sessions.retrieve(sessionId);
        const transactionId = session.payment_intent;

        const paymentExist = await paymentCollection.findOne({ transactionId });
        if (paymentExist)
          return res.json({
            message: "Payment already exists",
            transactionId,
            trackingId: session.metadata.trackingId,
          });

        if (session.payment_status === "paid") {
          const Issueid = session.metadata.Issueid;
          const trackingId = session.metadata.trackingId;

          // Update issue priority
          await issuesCollection.updateOne(
            { _id: new ObjectId(Issueid) },
            { $set: { priority: "high" } }
          );

          // Record payment
          const payment = {
            IssueId: Issueid,
            IssueName: session.metadata.Issuetitle,
            amount: session.amount_total / 100,
            currency: session.currency,
            customerEmail: session.customer_email,
            transactionId,
            paymentStatus: session.payment_status,
            paymentType: "Boosting",
            paidAt: new Date(),
            trackingId,
          };
          await paymentCollection.insertOne(payment);

          // Record tracking log
          const trackingExist = await trackingsCollection.findOne({
            transactionId,
            Boosting: "Boost the issue",
          });
          if (!trackingExist) {
            await trackingsCollection.insertOne({
              trackingId,
              transactionId,
              status: "pending",
              Boosting: "Boost the issue",
              updatedBy: Issueid,
              role: "citizen",
              message: "Issue boosted by citizen",
              createdAt: new Date(),
            });
          }

          return res.json({
            success: true,
            transactionId,
            trackingId,
            paymentInfo: payment,
          });
        }

        res.status(400).json({ message: "Payment not completed" });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Boost payment verification failed" });
      }
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
