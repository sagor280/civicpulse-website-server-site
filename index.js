const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
require("dotenv").config();

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET);
const admin = require("firebase-admin");





const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8')
const serviceAccount = JSON.parse(decoded);

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
    // await client.connect();
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

    const verifyStaff = async (req, res, next) => {
      try {
        const email = req.decoded_email;
        const user = await userCollection.findOne({ email });

        if (!user || user.role !== "staff") {
          return res.status(403).json({ message: "Staff access required" });
        }

        if (user.isBlocked) {
          return res.status(403).json({ message: "Staff is blocked" });
        }

        req.staff = user;
        next();
      } catch (err) {
        console.error("verifyStaff Error:", err);
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

    // Get user ID by email
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
          .sort({ isBoosted: -1, createdAt: -1 })
          .toArray();
        res.json(issues);
      } catch (err) {
        console.error("Get All Issues Error:", err);
        res.status(500).json({ message: "Failed to fetch issues" });
      }
    });

    app.get("/issues", async (req, res) => {
      let query = {};
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 6;
      const skip = (page - 1) * limit;
      const { status, priority, category, searchText } = req.query;
      if (searchText) {
        query.$or = [
          { title: { $regex: searchText, $options: "i" } },
          { category: { $regex: searchText, $options: "i" } },
          { location: { $regex: searchText, $options: "i" } },
        ];
      }

      if (status) {
        query.status = status;
      }
      if (priority) {
        query.priority = priority;
      }
      if (category) {
        query.category = category;
      }
      const total = await issuesCollection.countDocuments(query);
      const cursor = await issuesCollection
        .find(query)
        .skip(skip)
        .limit(limit)
        .toArray();
      res.send({
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
        issues: cursor,
      });
    });

    // ------------------- Upvote API -------------------

    app.patch("/issues/upvote/:id",verifyFBToken,checkBlockedUser,
      async (req, res) => {
        const id = req.params.id;

        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: "Invalid issue ID" });
        }

        const { email, createrEmail } = req.body;
        if (!email) return res.status(400).send({ message: "Log in first" });
        if (createrEmail === email)
          return res
            .status(400)
            .send({ message: "You can't upvote your own issue" });

        const issue = await issuesCollection.findOne({ _id: new ObjectId(id) });
        if (!issue) return res.status(404).send({ message: "Issue not found" });

        if (Array.isArray(issue.upvotes)) {
          await issuesCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { upvotes: issue.upvotes.length } }
          );
        }

        // Update upvote
        const result = await issuesCollection.updateOne(
          { _id: new ObjectId(id), upvotedBy: { $ne: email } },
          { $inc: { upvotes: 1 }, $addToSet: { upvotedBy: email } }
        );

        if (result.matchedCount === 0) {
          return res.status(400).send({ message: "Already upvoted" });
        }

        res.send({
          success: true,
          message: "Upvoted successfully",
        });
      }
    );

    app.get("/dashboard/citizen-stats", verifyFBToken, async (req, res) => {
      try {
        const email = req.decoded_email;
        const user = await userCollection.findOne({ email });
        if (!user) return res.status(404).json({ message: "User not found" });

        const userId = user._id.toString();

        const totalIssues = await issuesCollection.countDocuments({
          createdBy: userId,
        });
        const pendingIssues = await issuesCollection.countDocuments({
          createdBy: userId,
          status: "pending",
        });
        const inProgressIssues = await issuesCollection.countDocuments({
          createdBy: userId,
          status: "in-progress",
        });
        const resolvedIssues = await issuesCollection.countDocuments({
          createdBy: userId,
          status: "resolved",
        });

        const totalPayments = await paymentCollection.countDocuments({
          userId,
        });

        res.json({
          totalIssues,
          pendingIssues,
          inProgressIssues,
          resolvedIssues,
          totalPayments,
          isBlocked: user.isBlocked,
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
    });

    app.get("/dashboard/issues-stats",verifyFBToken,verifyAdmin,
      async (req, res) => {
        const stats = await issuesCollection
          .aggregate([
            {
              $group: {
                _id: null,
                total: { $sum: 1 },
                pending: {
                  $sum: { $cond: [{ $eq: ["$status", "pending"] }, 1, 0] },
                },
                resolved: {
                  $sum: { $cond: [{ $eq: ["$status", "resolved"] }, 1, 0] },
                },
                rejected: {
                  $sum: { $cond: [{ $eq: ["$status", "rejected"] }, 1, 0] },
                },
              },
            },
          ])
          .toArray();

        res.send(
          stats[0] || { total: 0, pending: 0, resolved: 0, rejected: 0 }
        );
      }
    );

    app.get("/dashboard/latest-issues",verifyFBToken,verifyAdmin,
      async (req, res) => {
        const latestIssues = await issuesCollection
          .aggregate([{ $sort: { createdAt: -1 } }, { $limit: 6 }])
          .toArray();

        res.send(latestIssues);
      }
    );

    app.get("/dashboard/payment-stats",verifyFBToken,verifyAdmin,
      async (req, res) => {
        const stats = await paymentCollection
          .aggregate([
            {
              $group: {
                _id: null,
                totalPayments: { $sum: 1 },
                totalAmount: { $sum: "$amount" },
              },
            },
          ])
          .toArray();

        res.send(stats[0] || { totalPayments: 0, totalAmount: 0 });
      }
    );

    // Latest Payments
    app.get("/dashboard/latest-payments",verifyFBToken,verifyAdmin,
      async (req, res) => {
        const latestPayments = await paymentCollection
          .aggregate([{ $sort: { createdAt: -1 } }, { $limit: 6 }])
          .toArray();

        res.send(latestPayments);
      }
    );

    app.get("/dashboard/latest-users",verifyFBToken,verifyAdmin,
      async (req, res) => {
        const latestUsers = await userCollection
          .aggregate([
            { $sort: { createdAt: -1 } },
            { $limit: 6 },
            { $project: { displayName: 1, name:1,customerEmail:1, email: 1, role: 1, createdAt: 1 } },
          ])
          .toArray();

        res.send(latestUsers);
     

      }
    );

    // ================= Staff Dashboard Stats =================
    app.get("/staff/dashboard/stats",verifyFBToken,verifyStaff,async (req, res) => {
        try {
          const email = req.staff.email;

          const assignedIssuesCount = await issuesCollection.countDocuments({
            "assignedStaff.email": email,
          });

          const resolvedIssuesCount = await issuesCollection.countDocuments({
            "assignedStaff.email": email,
            status: "resolved",
          });

          const pendingIssuesCount = await issuesCollection.countDocuments({
            "assignedStaff.email": email,
            status: "pending",
          });

          const todayStart = new Date();
          todayStart.setHours(0, 0, 0, 0);

          const todayEnd = new Date();
          todayEnd.setHours(23, 59, 59, 999);

          const todaysTasksCount = await issuesCollection.countDocuments({
            "assignedStaff.email": email,
            createdAt: { $gte: todayStart, $lte: todayEnd },
          });

          res.send({
            assignedIssuesCount,
            resolvedIssuesCount,
            pendingIssuesCount,
            todaysTasksCount,
          });
        } catch (err) {
          console.error("Staff Dashboard Stats Error:", err);
          res.status(500).json({ message: "Internal Server Error" });
        }
      }
    );

    // ================= Latest Assigned Issues =================
    app.get("/staff/dashboard/latest-issues",verifyFBToken,verifyStaff,
      async (req, res) => {
        try {
          const email = req.staff.email;

          const latestIssues = await issuesCollection
            .find({ "assignedStaff.email": email })
            .sort({ createdAt: -1 })
            .limit(5)
            .toArray();

          res.send(latestIssues);
        } catch (err) {
          console.error("Latest Staff Issues Error:", err);
          res.status(500).json({ message: "Internal Server Error" });
        }
      }
    );

    // ================= Staff Profile =================
    app.get("/staff/profile", verifyFBToken, verifyStaff, async (req, res) => {
      try {
        const user = req.staff;

        res.json({
          id: user._id.toString(),
          displayName: user.displayName,
          email: user.email,
          phone: user.phone || "",
          photoURL: user.photoURL || null,
          role: user.role,
        });
      } catch (err) {
        console.error("Get Staff Profile Error:", err);
        res.status(500).json({ message: "Internal Server Error" });
      }
    });

    // ------------------- Issue Details API -------------------
    app.get("/issues/:id", async (req, res) => {
  try {
    const issueId = req.params.id;

    const issue = await issuesCollection.findOne({
      _id: new ObjectId(issueId),
    });

    if (!issue) {
      return res.status(404).json({ message: "Issue not found" });
    }

    res.json(issue);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to fetch issue details" });
  }
});


    app.get("/users/staff", verifyFBToken, verifyAdmin, async (req, res) => {
      const staffs = await userCollection.find({ role: "staff" }).toArray();
      res.send(staffs);
    });

    app.get("/admin/users", verifyFBToken, verifyAdmin, async (req, res) => {
      const users = await userCollection.find({ role: "citizen" }).toArray();
      res.send(users);
    });

    app.get("/admin/profile", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const email = req.decoded_email;
        const user = await userCollection.findOne({ email });
        if (!user) return res.status(404).json({ message: "Admin not found" });
        res.json(user);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
    });

    // ================= Issue Timeline API =================
    app.get("/issues/:trackingId/timeline", verifyFBToken, async (req, res) => {
      try {
        const { trackingId } = req.params;

        const timeline = await trackingsCollection
          .find({ trackingId })
          .sort({ createdAt: 1 }) // oldest → newest
          .toArray();

        res.send(timeline);
      } catch (error) {
        console.error("Timeline fetch error:", error);
        res.status(500).json({ message: "Failed to load timeline" });
      }
    });

    // ------------------- Reject Issue (Admin) -------------------
    app.patch("/issues/reject/:id",verifyFBToken,verifyAdmin,
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

    app.patch("/issues/assign/:id",verifyFBToken,verifyAdmin,
      async (req, res) => {
        const issueId = req.params.id;
        const { staffEmail, staffName } = req.body;

        if (!staffEmail) {
          return res.status(400).send({ message: "Staff email is required" });
        }

        const result = await issuesCollection.updateOne(
          { _id: new ObjectId(issueId), status: "pending" },
          {
            $set: {
              assignedStaff: {
                email: staffEmail,
                name: staffName,
              },
              status: "assigned",
            },
          }
        );

        res.send(result);
      }
    );

    //admin user block & unblock api here......

    app.patch("/admin/users/block/:id",verifyFBToken,verifyAdmin,
      async (req, res) => {
        const { id } = req.params;
        const { isBlocked } = req.body;

        const result = await userCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { isBlocked } }
        );

        res.send(result);
      }
    );

    app.patch("/admin/users/unblock/:id",verifyFBToken,verifyAdmin,
      async (req, res) => {
        const id = req.params.id;

        const result = await userCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { isBlocked: false } }
        );

        res.send(result);
      }
    );

    app.post("/staff", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { displayName, email, password, phone, photoURL } = req.body;

        // Firebase Auth create
        const userRecord = await admin.auth().createUser({
          email,
          password,
          displayName,
          photoURL,
        });

        // Save in DB
        const staffData = {
          uid: userRecord.uid,
          displayName,
          email,
          phone,
          photoURL,
          role: "staff",
          isBlocked: false,
          createdAt: new Date(),
        };

        await userCollection.insertOne(staffData);

        res.send({ success: true, message: "Staff created successfully" });
      } catch (error) {
        res.status(500).send({ message: error.message });
      }
    });

    app.delete("/staff/:id", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const { id } = req.params;

        const staff = await userCollection.findOne({ _id: new ObjectId(id) });

        // Firebase delete
        await admin.auth().deleteUser(staff.uid);

        // DB delete
        await userCollection.deleteOne({ _id: new ObjectId(id) });

        res.send({ success: true, message: "Staff deleted" });
      } catch (error) {
        res.status(500).send({ message: error.message });
      }
    });

    app.patch("/staff/:id", verifyFBToken, async (req, res) => {
      try {
        const { id } = req.params;
        const { displayName, phone, photoURL } = req.body;
        const user = await userCollection.findOne({ _id: new ObjectId(id) });
        if (!user) return res.status(404).json({ message: "User not found" });

        if (req.decoded_email !== user.email) {
          const requester = await userCollection.findOne({
            email: req.decoded_email,
          });
          if (!requester || requester.role !== "admin") {
            return res.status(403).json({ message: "Access denied" });
          }
        }

        const updateDoc = {
          $set: {
            displayName,
            phone,
            ...(photoURL && { photoURL }),
            updatedAt: new Date(),
          },
        };

        const result = await userCollection.updateOne(
          { _id: new ObjectId(id) },
          updateDoc
        );

        res.json({
          success: true,
          message: "Profile updated successfully",
          result,
        });
      } catch (err) {
        console.error("Staff update error:", err);
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
        upvotes: 0,
        upvotedBy: [],
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
    app.delete("/issues/:id",verifyFBToken,checkBlockedUser,
      async (req, res) => {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const cursor = await issuesCollection.deleteOne(query);
        res.send(cursor);
      }
    );
    //issue update api

    app.patch("/issues/:id",verifyFBToken,checkBlockedUser,
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

      //Lates Issue api

    app.get('/issues/resolved/latest', async (req, res) => {
      const result = await issuesCollection
        .find({ status: "resolved" })
        .sort({ createdAt: -1 })
        .limit(6)
        .toArray();

      res.send(result);
    });


    // GET /staff/issues
    app.get("/staff/issues", verifyFBToken, verifyStaff, async (req, res) => {
      try {
        const issues = await issuesCollection
          .find({ "assignedStaff.email": req.staff.email })
          .sort({ priority: 1, createdAt: -1 })
          .toArray();
        res.json(issues);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Server error" });
      }
    });

    // PATCH /staff/issues/:id/status
    app.patch("/staff/issues/:id/status",verifyFBToken,verifyStaff,
      async (req, res) => {
        try {
          const issueId = req.params.id;
          const { status } = req.body;

          const issue = await issuesCollection.findOne({
            _id: new ObjectId(issueId),
          });
          if (!issue)
            return res.status(404).json({ message: "Issue not found" });

          // Allowed flow
          const flow = {
            assigned: ["in-progress"],
            pending: ["in-progress"],
            "in-progress": ["working"],
            working: ["resolved"],
            resolved: ["closed"],
          };

          if (!flow[issue.status]?.includes(status)) {
            return res.status(400).json({
              message: `Cannot change from ${issue.status} to ${status}`,
            });
          }

          // Update issue
          await issuesCollection.updateOne(
            { _id: new ObjectId(issueId) },
            { $set: { status, updatedAt: new Date() } }
          );

          // Add tracking
          await trackingsCollection.insertOne({
            trackingId: issue.trackingId,
            status,
            updatedBy: req.staff._id.toString(),
            role: "staff",
            message: `Status changed to ${status} by staff`,
            createdAt: new Date(),
          });

          res.json({ success: true });
        } catch (err) {
          console.error(err);
          res.status(500).json({ message: "Server error" });
        }
      }
    );

    // ------------------- Payment APIs -------------------

    // GET all payments (Admin)
    app.get("/payments", verifyFBToken, verifyAdmin, async (req, res) => {
      const { status, type } = req.query;
      const query = {};

      if (status) query.status = status;
      if (type) query.paymentType = type;

      const payments = await paymentCollection
        .find(query)
        .sort({ paidAt: -1 })
        .toArray();

      res.send(payments);
    });

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
    app.post("/payment-checkout-session/boosting",verifyFBToken,checkBlockedUser,
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
    app.patch("/payment-success/boosting", async (req, res) => {
      try {
        const sessionId = req.query.session_id;
        if (!sessionId) {
          return res.status(400).json({ message: "Session ID missing" });
        }

        const session = await stripe.checkout.sessions.retrieve(sessionId);
        const transactionId = session.payment_intent;

        const paymentExist = await paymentCollection.findOne({ transactionId });
        if (paymentExist) {
          return res.json({
            message: "Payment already exists",
            transactionId,
            trackingId: session.metadata.trackingId,
          });
        }

        if (session.payment_status !== "paid") {
          return res.status(400).json({ message: "Payment not completed" });
        }

        const Issueid = session.metadata.Issueid;
        const trackingId = session.metadata.trackingId;

        //  Check already boosted
        const issue = await issuesCollection.findOne({
          _id: new ObjectId(Issueid),
        });

        if (issue?.priority === "high") {
          return res.status(400).json({ message: "Issue already boosted" });
        }

        await issuesCollection.updateOne(
          { _id: new ObjectId(Issueid) },
          { $set: { priority: "high" } }
        );

        //  Save payment
        const payment = {
          email: session.customer_email,
          amount: session.amount_total / 100,
          currency: session.currency,
          transactionId,
          status: "success",
          paymentType: "Boosting",
          paidAt: new Date(),
          trackingId,
        };

        await paymentCollection.insertOne(payment);
        await trackingsCollection.insertOne({
          trackingId,
          transactionId,
          status: "boosted",
          message: "Issue boosted by citizen (৳100 payment)",
          updatedBy: session.customer_email,
          role: "citizen",
          createdAt: new Date(),
        });

        res.json({
          success: true,
          transactionId,
          trackingId,
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Boost payment verification failed" });
      }
    });

    app.patch("/payment-success", async (req, res) => {
      try {
        const sessionId = req.query.session_id;
        if (!sessionId) {
          return res.status(400).json({ message: "Session ID is required" });
        }

        // Retrieve session from Stripe
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        const transactionId = session.payment_intent;

        // Check if payment already exists
        const paymentExist = await paymentCollection.findOne({ transactionId });
        if (paymentExist) {
          return res.send({
            message: "Payment already exists",
            transactionId,
            trackingId: paymentExist.trackingId || null,
          });
        }
        const { email, userId } = session.metadata;

        if (session.payment_status === "paid") {
          const updateResult = await userCollection.updateOne(
            { _id: new ObjectId(userId) },
            { $set: { isPremium: true } }
          );
          const payment = {
            amount: session.amount_total / 100,
            currency: session.currency,
            customerEmail: email,
            userId,
            transactionId,
            paymentStatus: session.payment_status,
            paymentType: "Subscription",
            paidAt: new Date(),
            trackingId: userId,
          };

          const resultPayment = await paymentCollection.insertOne(payment);

          // Generate tracking
          const trackingId = generateTrackingId();
          await trackingsCollection.insertOne({
            trackingId,
            status: "paid",
            updatedBy: userId,
            role: "citizen",
            message: `User ${email} upgraded to premium`,
            createdAt: new Date(),
          });
          await paymentCollection.updateOne(
            { _id: resultPayment.insertedId },
            { $set: { trackingId } }
          );

          return res.send({
            success: true,
            modifyUser: updateResult,
            trackingId,
            transactionId,
            paymentInfo: resultPayment,
          });
        }

        return res.send({ success: false, message: "Payment not completed" });
      } catch (err) {
        console.error("Payment Success Error:", err);
        res.status(500).json({ message: "Internal Server Error" });
      }
    });
    // await client.db("admin").command({ ping: 1 });
    // console.log("Connected to MongoDB successfully!");
  } finally {
  }
}

run().catch(console.error);

app.get("/", (req, res) => res.send("civicpluse running...!"));

app.listen(port, () => console.log(`Server listening on port ${port}`));
