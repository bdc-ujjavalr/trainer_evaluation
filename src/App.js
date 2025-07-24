require("dotenv").config();
const express = require("express");
const path = require("path");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const axios = require("axios"); // For Airtable API calls
const fetch = require("node-fetch"); // For S3 uploads if using older presigned URL method
const { customAlphabet } = require("nanoid"); // For generating custom IDs
const {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
} = require("@aws-sdk/client-s3"); // AWS SDK v3 for S3
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner"); // For S3 presigned URLs

const app = express();
const PORT = process.env.PORT || 8000;
const basePath = "/trainer_evaluation"; // Define base path

// --- NanoID generators ---
const ALPHABET =
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const ORG_ID_LENGTH = 16;
const USER_ID_LENGTH = 16;
const orgNano = customAlphabet(ALPHABET, ORG_ID_LENGTH);
const userNano = customAlphabet(ALPHABET, USER_ID_LENGTH);

// --- MONGO + SESSIONS ---
if (!process.env.MONGODB_URI || !process.env.SESSION_SECRET) {
  console.error(
    "FATAL ERROR: MONGODB_URI and SESSION_SECRET must be defined in .env"
  );
  process.exit(1);
}
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB connected successfully"))
  .catch((err) => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// ── MODELS ────────────────────────────────────────────────
// Organization model: _id is a String like "orgXXXXXXXXXXXXXX"
const OrganizationSchema = new mongoose.Schema({
  _id: {
    type: String,
    default: () => "org" + orgNano(),
  },
  name: { type: String, required: true },
  createdBy: { type: String, ref: "User" },
  createdAt: { type: Date, default: Date.now },
});
const Organization = mongoose.model("Organization", OrganizationSchema);

// User model: _id is a String like "userXXXXXXXXXXXXXX"
const UserSchema = new mongoose.Schema({
  _id: {
    type: String,
    default: () => "user" + userNano(),
  },
  username: String,
  password: String,
  organizationId: { type: String, ref: "Organization" },
  organizationName: String,
  isOrgAdmin: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false },
});
// enforce unique username within each org
UserSchema.index({ username: 1, organizationId: 1 }, { unique: true });
UserSchema.index(
  { username: 1 },
  { unique: true, partialFilterExpression: { organizationId: null } }
);
const User = mongoose.model("User", UserSchema);

// TrainingContent model
const TrainingContentSchema = new mongoose.Schema({
  organizationId: { type: String, ref: "Organization" },
  organizationName: String,
  userId: { type: String, ref: "User" },
  userName: String,
  training: String,
  trainingContentOption: String,
  trainingContent: String,
  requiredQualifications: String,
  attachmentUrl: String,
  filename: String,
  airtableRecordId: String,
  createdAt: { type: Date, default: Date.now },
});
const TrainingContent = mongoose.model(
  "TrainingContent",
  TrainingContentSchema
);

// TrainerEvaluation model
const TrainerEvaluationSchema = new mongoose.Schema({
  organizationId: { type: String, ref: "Organization" },
  organizationName: String,
  userId: { type: String, ref: "User" },
  userName: String,
  firstName: String,
  lastName: String,
  phoneNumber: String,
  trainerEmail: String,
  receiveReview: String,
  trainingId: String,
  trainingName: String,
  airtableRecordId: String,
  resumeUrl: String,
  filename: String,
  interviewStatus: {
    type: String,
    enum: ["pending", "ended", "airtable_record_not_found"], // Added new possible status
    default: "pending",
  },
  transcript: { type: String, default: "" },
  interviewRecordingUrl: { type: String, default: "" },
  callendReason: { type: String, default: "" },
  summary: { type: String, default: "" },
  cost: { type: Number, default: 0 },
  callStartedAt: Date,
  callEndedAt: Date,
  callId: String,
  createdAt: { type: Date, default: Date.now },
});
const TrainerEvaluation = mongoose.model(
  "TrainerEvaluation",
  TrainerEvaluationSchema
);

// ── BACKUP MODELS ─────────────────────────────────────────

// BackupOrganization model
const BackupOrganization = mongoose.model(
  "BackupOrganization",
  new mongoose.Schema({
    originalId: String,
    name: String,
    createdBy: String,
    createdAt: Date,
    backupCreatedAt: { type: Date, default: Date.now },
  })
);

// BackupUser model
const BackupUser = mongoose.model(
  "BackupUser",
  new mongoose.Schema({
    originalId: String,
    username: String,
    password: String,
    organizationId: String,
    organizationName: String,
    isOrgAdmin: Boolean,
    isAdmin: Boolean,
    backupCreatedAt: { type: Date, default: Date.now },
  })
);

// BackupTrainingContent model
const BackupTrainingContent = mongoose.model(
  "BackupTrainingContent",
  new mongoose.Schema({
    originalId: String,
    organizationId: String,
    organizationName: String,
    userId: String,
    userName: String,
    training: String,
    trainingContentOption: String,
    trainingContent: String,
    requiredQualifications: String,
    attachmentUrl: String,
    filename: String,
    airtableRecordId: String,
    createdAt: Date,
    backupCreatedAt: { type: Date, default: Date.now },
  })
);

// BackupTrainerEvaluation model
const BackupTrainerEvaluation = mongoose.model(
  "BackupTrainerEvaluation",
  new mongoose.Schema({
    originalId: String,
    organizationId: String,
    organizationName: String,
    userId: String,
    userName: String,
    firstName: String,
    lastName: String,
    phoneNumber: String,
    trainerEmail: String,
    receiveReview: String,
    trainingId: String,
    trainingName: String,
    airtableRecordId: String,
    resumeUrl: String,
    filename: String,
    interviewStatus: {
      type: String,
      enum: ["pending", "ended", "airtable_record_not_found"],
      default: "pending",
    },
    transcript: { type: String, default: "" },
    interviewRecordingUrl: { type: String, default: "" },
    callendReason: { type: String, default: "" },
    summary: { type: String, default: "" },
    cost: { type: Number, default: 0 },
    callStartedAt: Date,
    callEndedAt: Date,
    callId: String,
    createdAt: Date,
    backupCreatedAt: { type: Date, default: Date.now },
  })
);

// --- MIDDLEWARE: Body Parsers & Session ---
app.use(express.urlencoded({ extended: true, limit: "50mb" }));
app.use(express.json({ limit: "50mb" }));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false, // Don't save session if unmodified
    saveUninitialized: false, // Don't create session until something stored
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      ttl: 14 * 24 * 60 * 60, // 14 days
      autoRemove: "native",
    }),
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 14 * 24 * 60 * 60 * 1000,
      sameSite: "lax",
      path: basePath, // IMPORTANT: Set cookie path to basePath
    },
  })
);

// --- AUTH ROUTES ---
app.get(basePath + "/login", (req, res) => {
  if (req.session.userId) {
    return res.redirect(basePath + "/"); // Already logged in, redirect to dashboard
  }
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.post(basePath + "/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.redirect(basePath + "/login?error=credentials_missing");
  }
  try {
    const user = await User.findOne({
      username: username.trim().toLowerCase(),
    });

    if (user && (await bcrypt.compare(password, user.password))) {
      req.session.regenerate(async (err) => {
        if (err) {
          console.error("Session regeneration error:", err);
          return res.redirect(basePath + "/login?error=session_error");
        }
        req.session.userId = user._id.toString();
        req.session.username = user.username;
        req.session.isAdmin = user.isAdmin || false;
        req.session.isOrgAdmin = user.isOrgAdmin || false;

        if (user.organizationId) {
          req.session.organizationId = user.organizationId.toString();
          const org = await Organization.findById(user.organizationId);
          req.session.organizationName = org ? org.name : user.organizationName;
        } else {
          req.session.organizationId = null;
          req.session.organizationName = null;
        }

        console.log(
          `User '${user.username}' logged in. Admin: ${req.session.isAdmin}, OrgAdmin: ${req.session.isOrgAdmin}`
        );
        res.redirect(basePath + "/");
      });
    } else {
      console.warn(`Login attempt failed for username: ${username}`);
      res.redirect(basePath + "/login?error=invalid_credentials");
    }
  } catch (err) {
    console.error("Login process error:", err);
    res.redirect(basePath + "/login?error=server_error");
  }
});

app.get(basePath + "/logout", (req, res) => {
  const username = req.session.username || "User";
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err);
      return res.status(500).send("Could not log out properly.");
    }
    res.clearCookie("connect.sid", { path: basePath }); // IMPORTANT: Clear cookie with correct path
    console.log(`User '${username}' logged out.`);
    res.redirect(basePath + "/login");
  });
});

// --- SESSION-INFO HELPER (for client-side checks) ---
app.get(basePath + "/session-info", async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({
      isAuthenticated: false,
      error: "Not authenticated. No active session.",
      isAdmin: false,
      isOrgAdmin: false,
    });
  }
  try {
    const user = await User.findById(req.session.userId).populate(
      "organizationId",
      "name"
    );
    if (!user) {
      return req.session.destroy(() => {
        res.clearCookie("connect.sid", { path: basePath });
        res.status(401).json({
          isAuthenticated: false,
          error: "User associated with session not found.",
          isAdmin: false,
          isOrgAdmin: false,
        });
      });
    }
    req.session.isAdmin = user.isAdmin || false;
    req.session.isOrgAdmin = user.isOrgAdmin || false;
    req.session.username = user.username;

    let orgDetails = { organizationId: null, organizationName: null };
    if (user.organizationId) {
      orgDetails.organizationId =
        typeof user.organizationId === "object"
          ? user.organizationId._id.toString()
          : user.organizationId.toString();
      orgDetails.organizationName =
        typeof user.organizationId === "object"
          ? user.organizationId.name
          : user.organizationName;
      req.session.organizationId = orgDetails.organizationId;
      req.session.organizationName = orgDetails.organizationName;
    }

    res.json({
      isAuthenticated: true,
      userId: user._id.toString(),
      username: user.username,
      isAdmin: user.isAdmin || false,
      isOrgAdmin: user.isOrgAdmin || false,
      ...orgDetails,
    });
  } catch (err) {
    console.error("Error fetching data for /session-info:", err);
    res.status(500).json({
      isAuthenticated: false,
      error: "Server error fetching session data.",
      isAdmin: false,
      isOrgAdmin: false,
    });
  }
});

// --- AUTHENTICATION MIDDLEWARE (Global protection for routes below) ---
app.use((req, res, next) => {
  // If the request is not for our application base path, let it go.
  // Exception for "/" which might be an initial redirect or health check.
  if (req.path !== "/" && !req.path.startsWith(basePath)) {
    return next();
  }

  let operationalPath = req.path; // Normalize path for checks if it's under basePath
  if (req.path.startsWith(basePath)) {
    operationalPath = req.path.substring(basePath.length) || "/";
  }

  const publicRelativePaths = ["/login", "/logout", "/session-info"];

  if (publicRelativePaths.includes(operationalPath)) {
    return next();
  } // Allow access to static files (e.g., CSS for login page)

  if (
    req.method === "GET" &&
    operationalPath.includes(".") &&
    !operationalPath.startsWith("/api/")
  ) {
    return next();
  }

  if (!req.session.userId) {
    if (operationalPath.startsWith("/api/")) {
      return res.status(401).json({ error: "Not authenticated" });
    }
    return res.redirect(basePath + "/login");
  }
  next();
});

// --- MAIN APPLICATION ROUTE (Dashboard) ---
app.get(basePath + "/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// --- OPTIONAL: EXPLICIT DASHBOARD ROUTE ---
app.get(basePath + "/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// --- HELPER: getSessionContext (for internal API logic) ---
async function getSessionContext(req, resForErrorHandling) {
  if (!req.session.userId) {
    if (resForErrorHandling && !resForErrorHandling.headersSent) {
      return resForErrorHandling
        .status(401)
        .json({ error: "Not authenticated" });
    }
    return null;
  }
  try {
    const user = await User.findById(req.session.userId).populate(
      "organizationId",
      "name"
    );
    if (!user) {
      if (resForErrorHandling && !resForErrorHandling.headersSent) {
        return req.session.destroy(() => {
          resForErrorHandling.clearCookie("connect.sid", { path: basePath });
          resForErrorHandling
            .status(401)
            .json({ error: "User from session not found." });
        });
      }
      return null;
    }
    return {
      userId: user._id.toString(),
      userName: user.username,
      organizationId: user.organizationId
        ? user.organizationId._id
          ? user.organizationId._id.toString()
          : user.organizationId.toString()
        : null,
      organizationName: user.organizationId
        ? user.organizationId.name || user.organizationName
        : null,
      isOrgAdmin: user.isOrgAdmin || false,
      isAdmin: user.isAdmin || false,
    };
  } catch (error) {
    console.error("Error in getSessionContext:", error);
    if (resForErrorHandling && !resForErrorHandling.headersSent) {
      resForErrorHandling
        .status(500)
        .json({ error: "Server error processing session context." });
    }
    return null;
  }
}

// --- HELPER: Middleware for API routes needing Super Admin ---
async function ensureSuperAdmin(req, res, next) {
  const ctx = await getSessionContext(req, res);
  if (ctx && ctx.isAdmin) {
    return next();
  }
  if (!res.headersSent) {
    res
      .status(403)
      .json({ error: "Access Denied: Super-user privileges required." });
  }
}

// Middleware: allow Super-Admins or Org-Admins for their own org
async function ensureOrgAdminOrSuperAdmin(req, res, next) {
  const ctx = await getSessionContext(req, res);
  if (!ctx) {
    if (!res.headersSent) {
      return res.status(401).json({ error: "Not authenticated" });
    }
    return;
  }

  if (ctx.isAdmin) {
    return next();
  }

  if (ctx.isOrgAdmin) {
    return next();
  }

  if (!res.headersSent) {
    return res
      .status(403)
      .json({ error: "Access Denied: Org-Admin or Super-Admin only." });
  }
}

// --- ADMIN OPERATIONS (Example: Create Org - requires Super Admin) ---
app.get(basePath + "/create-organization", ensureSuperAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "create-organization.html"));
});

app.post(
  basePath + "/create-organization",
  ensureSuperAdmin,
  async (req, res) => {
    const { name } = req.body;
    const ctx = await getSessionContext(req);
    if (!name)
      return res
        .status(400)
        .redirect(basePath + "/create-organization?error=Name+is+required");
    try {
      const newOrg = await Organization.create({
        name,
        createdBy: ctx ? ctx.userId : null,
      });
      await BackupOrganization.create({
        originalId: newOrg._id,
        name: newOrg.name,
        createdBy: newOrg.createdBy,
        createdAt: newOrg.createdAt,
      });
      res.redirect(
        basePath +
          "/create-organization?success=Organization+" +
          encodeURIComponent(newOrg.name) +
          "+created"
      );
    } catch (err) {
      console.error("Error creating organization:", err);
      res
        .status(500)
        .redirect(basePath + "/create-organization?error=Server+error");
    }
  }
);

app.get(basePath + "/create-user", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "create-user.html"))
);

app.post(basePath + "/create-user", async (req, res) => {
  const me = await User.findById(req.session.userId);
  if (!me) {
    return res.status(401).send("Authentication error.");
  }
  const { username, password, organizationId } = req.body;

  const canCreate =
    me.isAdmin ||
    (me.isOrgAdmin &&
      me.organizationId &&
      me.organizationId.toString() === organizationId);

  if (!canCreate) {
    return res
      .status(403)
      .send(
        "Only super-user or org-admin for the selected organization may add users."
      );
  }
  if (!organizationId && !me.isAdmin) {
    return res.redirect(basePath + "/create-user?error=Select+org");
  }
  if (
    await User.exists({
      username: username.trim().toLowerCase(),
      organizationId,
    })
  ) {
    return res.redirect(
      basePath + "/create-user?error=Username+already+in+this+organization"
    );
  }

  try {
    const org = await Organization.findById(organizationId);
    if (!org && organizationId) {
      return res.redirect(basePath + "/create-user?error=Invalid+org");
    }
    const hash = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      username: username.trim().toLowerCase(),
      password: hash,
      organizationId: organizationId || null,
      organizationName: org ? org.name : null,
    });

    await BackupUser.create({
      originalId: newUser._id,
      username: newUser.username,
      password: newUser.password,
      organizationId: newUser.organizationId,
      organizationName: newUser.organizationName,
      isOrgAdmin: newUser.isOrgAdmin,
      isAdmin: newUser.isAdmin,
    });
    const msg =
      `User+${encodeURIComponent(username)}+created` +
      (org ? `+in+${encodeURIComponent(org.name)}` : "");
    res.redirect(basePath + "/create-user?success=" + msg);
  } catch (err) {
    console.error(err);
    res.redirect(basePath + "/create-user?error=Server+error");
  }
});

// API: List organizations
app.get(basePath + "/api/organizations", async (req, res) => {
  try {
    const orgs = await Organization.find().select("_id name");
    res.json(orgs);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Could not load orgs" });
  }
});

// API: List users in one organization
app.get(
  basePath + "/api/organizations/:orgId/users",
  ensureOrgAdminOrSuperAdmin,
  async (req, res) => {
    const ctx = await getSessionContext(req, res);
    if (!ctx) return;

    const { orgId } = req.params;

    if (!ctx.isAdmin && ctx.organizationId !== orgId) {
      return res
        .status(403)
        .json({ error: "Access denied to this organization's users." });
    }

    try {
      const users = await User.find({
        organizationId: orgId,
      }).select("_id username isOrgAdmin");
      res.json(users);
    } catch (err) {
      console.error(err);
      res
        .status(500)
        .json({ error: "Could not load users for that organization" });
    }
  }
);

// API: List trainings *for this user’s organization*
app.get(basePath + "/api/training-contents", async (req, res) => {
  const ctx = await getSessionContext(req, res);
  if (!ctx) return;

  try {
    const filter = ctx.isAdmin ? {} : { organizationId: ctx.organizationId };
    if (!ctx.organizationId && !ctx.isAdmin) {
      return res.json([]);
    }

    if (ctx.isAdmin || ctx.isOrgAdmin) {
      const contents = await TrainingContent.find(filter)
        .populate([
          { path: "userId", select: "username _id" },
          { path: "organizationId", select: "name _id" },
        ])
        .sort({ createdAt: -1 })
        .lean();
      return res.json(contents);
    }

    const list = await TrainingContent.find(
      { organizationId: ctx.organizationId },
      "training airtableRecordId"
    );
    return res.json(list);
  } catch (err) {
    console.error("Error fetching training contents:", err);
    return res.status(500).json({ error: "Failed to fetch training contents" });
  }
});

// Promote a user to org-admin (super-user only)
app.post(
  basePath + "/api/organizations/:orgId/users/:userId/make-admin",
  ensureSuperAdmin,
  async (req, res) => {
    const { orgId, userId } = req.params;
    const user = await User.findById(userId);
    if (
      !user ||
      (user.organizationId && user.organizationId.toString() !== orgId)
    ) {
      return res
        .status(404)
        .json({ error: "User not in that org, or user/org mismatch" });
    }
    await User.updateMany(
      { organizationId: orgId, isOrgAdmin: true },
      { $set: { isOrgAdmin: false } }
    );
    user.isOrgAdmin = true;
    await user.save();

    await BackupUser.updateMany(
      {
        organizationId: orgId,
        isOrgAdmin: true,
        originalId: { $ne: user._id },
      },
      { $set: { isOrgAdmin: false } }
    );
    await BackupUser.updateOne(
      { originalId: user._id },
      { $set: { isOrgAdmin: true } },
      { upsert: true }
    );
    res.json({ success: true, promoted: user.username });
  }
);

// DELETE a user
app.delete(
  basePath + "/api/organizations/:orgId/users/:userId",
  async (req, res) => {
    if (!req.session.userId)
      return res.status(401).json({ error: "Not authenticated" });

    const { orgId, userId } = req.params;
    const me = await User.findById(req.session.userId);
    if (!me) {
      return res.status(401).json({ error: "Authenticated user not found." });
    }

    const target = await User.findById(userId);
    if (!target) {
      return res.status(404).json({ error: "User not found" });
    }

    if (
      (target.organizationId && target.organizationId.toString() !== orgId) ||
      (!target.organizationId && orgId !== "null" && orgId !== null)
    ) {
      return res
        .status(404)
        .json({ error: "User not in that organization or orgId mismatch" });
    }

    if (me.isAdmin) {
      if (target.isAdmin && target._id.toString() === me._id.toString()) {
        return res
          .status(403)
          .json({ error: "Super admins cannot delete themselves." });
      }
      await User.deleteOne({ _id: userId }); // Also delete from BackupUser // await BackupUser.deleteOne({ originalId: userId });
      return res.json({ success: true });
    }

    if (
      me.isOrgAdmin &&
      me.organizationId &&
      me.organizationId.toString() === orgId
    ) {
      if (target.isOrgAdmin) {
        return res.status(403).json({
          error:
            "Org admin cannot delete another org-admin user of the same org.",
        });
      }
      if (me._id.toString() === target._id.toString()) {
        return res.status(403).json({
          error: "You cannot delete your own account via this method.",
        });
      }
      await User.deleteOne({ _id: userId }); // Also delete from BackupUser // await BackupUser.deleteOne({ originalId: userId });
      return res.json({ success: true });
    }

    return res.status(403).json({ error: "Forbidden" });
  }
);

// DELETE an organization (super‐user only), and all its data
app.delete(
  basePath + "/api/organizations/:orgId",
  ensureSuperAdmin,
  async (req, res) => {
    try {
      const { orgId } = req.params; // Backup related data before deleting

      const orgToBackup = await Organization.findById(orgId).lean();
      if (orgToBackup) {
        // Check if already backed up to avoid duplicates if this runs multiple times on error
        const existingBackup = await BackupOrganization.findOne({
          originalId: orgId,
        }).lean();
        if (!existingBackup) {
          await BackupOrganization.create({
            ...orgToBackup,
            originalId: orgToBackup._id,
            backupCreatedAt: new Date(),
          });
        }
      }

      const usersToBackup = await User.find({ organizationId: orgId }).lean();
      if (usersToBackup.length > 0) {
        const backupUsersOps = usersToBackup.map((u) => ({
          updateOne: {
            filter: { originalId: u._id },
            update: {
              $set: { ...u, originalId: u._id, backupCreatedAt: new Date() },
            },
            upsert: true,
          },
        }));
        await BackupUser.bulkWrite(backupUsersOps);
      }

      const trainingContentsToBackup = await TrainingContent.find({
        organizationId: orgId,
      }).lean();
      if (trainingContentsToBackup.length > 0) {
        const backupTrainingOps = trainingContentsToBackup.map((tc) => ({
          updateOne: {
            filter: { originalId: tc._id },
            update: {
              $set: { ...tc, originalId: tc._id, backupCreatedAt: new Date() },
            },
            upsert: true,
          },
        }));
        await BackupTrainingContent.bulkWrite(backupTrainingOps);
      }

      const trainerEvaluationsToBackup = await TrainerEvaluation.find({
        organizationId: orgId,
      }).lean();
      if (trainerEvaluationsToBackup.length > 0) {
        const backupEvalOps = trainerEvaluationsToBackup.map((te) => ({
          updateOne: {
            filter: { originalId: te._id },
            update: {
              $set: { ...te, originalId: te._id, backupCreatedAt: new Date() },
            },
            upsert: true,
          },
        }));
        await BackupTrainerEvaluation.bulkWrite(backupEvalOps);
      } // Now delete original data

      await TrainingContent.deleteMany({ organizationId: orgId });
      await TrainerEvaluation.deleteMany({ organizationId: orgId });
      await User.deleteMany({ organizationId: orgId });
      await Organization.findByIdAndDelete(orgId);

      res.json({
        success: true,
        message: `Organization ${orgId} and all associated data deleted and backed up.`,
      });
    } catch (err) {
      console.error("DELETE org cascade error:", err);
      res
        .status(500)
        .json({ error: "Could not delete organization and its data" });
    }
  }
);

// --- API ROUTES FOR DASHBOARD DATA ---
app.get(
  basePath + "/api/all-organizations",
  ensureSuperAdmin,
  async (req, res) => {
    try {
      const organizations = await Organization.find({})
        .populate({ path: "createdBy", select: "username _id" })
        .sort({ createdAt: -1 })
        .lean();
      res.json(organizations);
    } catch (err) {
      console.error("Error fetching all organizations:", err);
      res.status(500).json({ error: "Failed to fetch organizations" });
    }
  }
);

app.get(basePath + "/api/all-users", ensureSuperAdmin, async (req, res) => {
  try {
    const users = await User.find({})
      .populate({ path: "organizationId", select: "name _id" })
      .sort({ username: 1 })
      .lean();
    res.json(users);
  } catch (err) {
    console.error("Error fetching all users:", err);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

app.get(
  basePath + "/api/all-training-contents",
  ensureSuperAdmin,
  async (req, res) => {
    try {
      const trainingContents = await TrainingContent.find({})
        .populate([
          { path: "userId", select: "username _id" },
          { path: "organizationId", select: "name _id" },
        ])
        .sort({ createdAt: -1 })
        .lean();
      res.json(trainingContents);
    } catch (err) {
      console.error("Error fetching all training contents:", err);
      res.status(500).json({ error: "Failed to fetch training contents" });
    }
  }
);

app.get(
  basePath + "/api/all-trainer-evaluations",
  ensureSuperAdmin,
  async (req, res) => {
    try {
      const trainerEvaluations = await TrainerEvaluation.find({})
        .populate([
          { path: "userId", select: "username _id" },
          { path: "organizationId", select: "name _id" },
        ])
        .sort({ createdAt: -1 })
        .lean();
      res.json(trainerEvaluations);
    } catch (err) {
      console.error("Error fetching all trainer evaluations:", err);
      res.status(500).json({ error: "Failed to fetch trainer evaluations" });
    }
  }
);

// API for OrgAdmins or SuperAdmins to get users (filtered for OrgAdmins)
app.get(
  basePath + "/api/users",
  ensureOrgAdminOrSuperAdmin,
  async (req, res) => {
    const ctx = await getSessionContext(req, res);
    if (!ctx) return;

    const filter = ctx.isAdmin ? {} : { organizationId: ctx.organizationId };
    if (!ctx.organizationId && !ctx.isAdmin) {
      return res.json([]);
    }

    const users = await User.find(filter)
      .populate({ path: "organizationId", select: "name _id" })
      .sort({ username: 1 })
      .lean();

    res.json(users);
  }
);

// API for OrgAdmins or SuperAdmins to get evaluations (filtered for OrgAdmins)
app.get(
  basePath + "/api/trainer-evaluations",
  ensureOrgAdminOrSuperAdmin,
  async (req, res) => {
    const ctx = await getSessionContext(req, res);
    if (!ctx) return;

    const filter = ctx.isAdmin ? {} : { organizationId: ctx.organizationId };
    if (!ctx.organizationId && !ctx.isAdmin) {
      return res.json([]);
    }

    const evals = await TrainerEvaluation.find(filter)
      .populate([
        { path: "userId", select: "username _id" },
        { path: "organizationId", select: "name _id" },
      ])
      .sort({ createdAt: -1 })
      .lean();

    res.json(evals);
  }
);

// ── AWS + AIRTABLE SETUP ──────────────────────────────────
const FILE_SIZE_LIMIT = 50 * 1024 * 1024;
const {
  AWS_REGION = "ap-south-1",
  AWS_ACCESS_KEY_ID,
  AWS_SECRET_ACCESS_KEY,
  S3_BUCKET,
  AIRTABLE_BASE_ID,
  AIRTABLE_TABLE_NAME = "Training Details",
  EMP_TABLE = "emp_data",
  AIRTABLE_API_KEY,
} = process.env;

if (!AWS_ACCESS_KEY_ID || !AWS_SECRET_ACCESS_KEY || !S3_BUCKET) {
  console.error("Missing AWS creds"); // process.exit(1); // Comment out for dev if S3 not primary focus of testing
}
if (!AIRTABLE_BASE_ID || !AIRTABLE_API_KEY) {
  console.error("Missing Airtable creds"); // process.exit(1); // Comment out for dev if Airtable not primary focus
}
const s3Client = new S3Client({
  region: AWS_REGION,
  credentials: {
    accessKeyId: AWS_ACCESS_KEY_ID,
    secretAccessKey: AWS_SECRET_ACCESS_KEY,
  },
});

// S3 presign
app.get(basePath + "/presign", async (req, res) => {
  const { filename, filetype } = req.query;
  if (!filename || !filetype)
    return res.status(400).json({ error: "filename and filetype required" });
  const key = `trainer-details/${Date.now()}_${filename}`;
  const put = new PutObjectCommand({
    Bucket: S3_BUCKET,
    Key: key,
    ContentType: filetype,
  });
  const get = new GetObjectCommand({ Bucket: S3_BUCKET, Key: key });
  try {
    const uploadUrl = await getSignedUrl(s3Client, put, { expiresIn: 3600 });
    const downloadUrl = await getSignedUrl(s3Client, get, { expiresIn: 3600 });
    res.json({ uploadUrl, downloadUrl, key }); // also return key for reference
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// --- MODIFIED CODE ---
// Submit training content
app.post(basePath + "/submit-training-content", async (req, res) => {
  const ctx = await getSessionContext(req, res);
  if (!ctx) return;
  if (!ctx.organizationId) {
    return res
      .status(400)
      .send("User must belong to an organization to submit training content.");
  }

  const {
    training,
    trainingContentOption,
    trainingContent,
    requiredQualifications,
    filename,
    filetype,
    filedata,
  } = req.body;

  let attachmentUrl = null;
  if (trainingContentOption === "Attach PDF File" && filename && filedata) {
    try {
      const buf = Buffer.from(filedata, "base64");
      const key = `trainer-details/${
        ctx.organizationName
      }/${Date.now()}_${filename}`;
      const putCmd = new PutObjectCommand({
        Bucket: S3_BUCKET,
        Key: key,
        Body: buf,
        ContentType: filetype,
      });
      await s3Client.send(putCmd);
      attachmentUrl = `https://${S3_BUCKET}.s3.${AWS_REGION}.amazonaws.com/${key}`;
    } catch (e) {
      console.error("S3 direct upload error:", e);
      return res.status(500).send("S3 error: " + e.message);
    }
  }

  const airtPayload = {
    records: [
      {
        fields: {
          "Organization ID": ctx.organizationId,
          "Organization Name": ctx.organizationName,
          "User ID": ctx.userId,
          "User Name": ctx.userName,
          Training: training || "",
          "Training Content Option": trainingContentOption || "",
          "Training Content":
            trainingContentOption === "Enter Text" ? trainingContent : "",
          "Required Qualifications": requiredQualifications || "",
          ...(attachmentUrl && {
            "Training Content Attachment": [{ url: attachmentUrl, filename }],
          }),
        },
      },
    ],
  };

  let airtId;
  try {
    const atRes = await axios.post(
      `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(
        AIRTABLE_TABLE_NAME
      )}`,
      airtPayload,
      {
        headers: {
          Authorization: `Bearer ${AIRTABLE_API_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );
    airtId = atRes.data.records[0].id;
  } catch (e) {
    // Improved Error Logging
    console.error("--- AIRTABLE ERROR (Training Content) ---");
    let errorMessage = "Airtable error creating training content.";
    if (e.response) {
      console.error("Status:", e.response.status);
      console.error("Data:", JSON.stringify(e.response.data, null, 2));
      errorMessage = `Airtable Error: ${
        e.response.data?.error?.message || JSON.stringify(e.response.data)
      }`;
    } else {
      console.error("Error Message:", e.message);
      errorMessage = e.message;
    }
    console.error("--- END OF AIRTABLE ERROR ---");
    return res.status(500).send(errorMessage);
  }

  try {
    const newContent = await TrainingContent.create({
      organizationId: ctx.organizationId,
      organizationName: ctx.organizationName,
      userId: ctx.userId,
      userName: ctx.userName,
      training,
      trainingContentOption,
      trainingContent:
        trainingContentOption === "Enter Text" ? trainingContent : "",
      requiredQualifications,
      attachmentUrl,
      filename: trainingContentOption === "Attach PDF File" ? filename : null,
      airtableRecordId: airtId,
    });

    await BackupTrainingContent.create({
      originalId: newContent._id,
      organizationId: newContent.organizationId,
      organizationName: newContent.organizationName,
      userId: newContent.userId,
      userName: newContent.userName,
      training: newContent.training,
      trainingContentOption: newContent.trainingContentOption,
      trainingContent: newContent.trainingContent,
      requiredQualifications: newContent.requiredQualifications,
      attachmentUrl: newContent.attachmentUrl,
      filename: newContent.filename,
      airtableRecordId: newContent.airtableRecordId,
      createdAt: newContent.createdAt,
    });
  } catch (e) {
    console.error("Mongo error (Training Content):", e); // Rollback: Attempt to delete from Airtable if Mongo fails
    if (airtId) {
      console.log(`Attempting to delete orphaned Airtable record: ${airtId}`);
      try {
        await axios.delete(
          `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(
            AIRTABLE_TABLE_NAME
          )}/${airtId}`,
          {
            headers: { Authorization: `Bearer ${AIRTABLE_API_KEY}` },
          }
        );
        console.log(`Successfully deleted orphaned Airtable record: ${airtId}`);
      } catch (rollbackError) {
        console.error(
          `Failed to delete orphaned Airtable record ${airtId}:`,
          rollbackError.response?.data || rollbackError.message
        );
      }
    } // Still send an error response to the user
    return res.status(500).send("Database error saving training content.");
  }
  res.send("Training content submitted successfully!");
});

// Submit trainer evaluation
app.post(basePath + "/submit-trainer-evaluation", async (req, res) => {
  const ctx = await getSessionContext(req, res);
  if (!ctx) return;
  if (!ctx.organizationId) {
    return res
      .status(400)
      .send("User must belong to an organization to submit evaluations.");
  }

  const {
    firstName,
    lastName,
    phoneNumber,
    trainerEmail,
    receiveReview,
    trainingId,
    trainingName,
    filename,
    filetype,
    filedata,
    interviewStatus = "pending",
  } = req.body;

  let resumeUrl = null;
  if (filename && filedata) {
    try {
      const buf = Buffer.from(filedata, "base64");
      const key = `trainer-evaluations/${
        ctx.organizationName
      }/${Date.now()}_${filename}`;
      const putCmd = new PutObjectCommand({
        Bucket: S3_BUCKET,
        Key: key,
        Body: buf,
        ContentType: filetype,
      });
      await s3Client.send(putCmd);
      resumeUrl = `https://${S3_BUCKET}.s3.${AWS_REGION}.amazonaws.com/${key}`;
    } catch (e) {
      console.error("S3 error (Trainer Evaluation):", e);
      return res.status(500).send("S3 error: " + e.message);
    }
  }

  const airtEvalPayload = {
    records: [
      {
        fields: {
          "Organization ID": ctx.organizationId,
          "Organization Name": ctx.organizationName,
          "User ID": ctx.userId,
          "User Name": ctx.userName,
          "Interview Status": interviewStatus,
          fldi8oMr5mGrRfQP7: firstName,
          fldbylIkH26UXs5at: lastName,
          fldDFv60Y7cLOEa8V: phoneNumber,
          fldFpI2KDkHRU3As0: trainerEmail,
          fldCxI61bBlbdSgJ0: receiveReview,
          fldh5r6txdMBSWtyy: trainingId ? [trainingId] : undefined,
          fldinjg7iqV8aTjpB: resumeUrl
            ? [{ url: resumeUrl, filename }]
            : undefined,
        },
      },
    ],
  };

  let airtEvalId;
  try {
    const er = await axios.post(
      `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(
        EMP_TABLE
      )}`,
      airtEvalPayload,
      {
        headers: {
          Authorization: `Bearer ${AIRTABLE_API_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );
    airtEvalId = er.data.records[0].id;
  } catch (e) {
    // Improved Error Logging
    console.error("--- AIRTABLE ERROR (Trainer Evaluation) ---");
    let errorMessage = "Airtable error creating trainer evaluation.";
    if (e.response) {
      console.error("Status:", e.response.status);
      console.error("Data:", JSON.stringify(e.response.data, null, 2));
      errorMessage = `Airtable Error: ${
        e.response.data?.error?.message || JSON.stringify(e.response.data)
      }`;
    } else {
      console.error("Error Message:", e.message);
      errorMessage = e.message;
    }
    console.error("--- END OF AIRTABLE ERROR ---");
    return res.status(500).send(errorMessage);
  }

  try {
    const newEval = await TrainerEvaluation.create({
      organizationId: ctx.organizationId,
      organizationName: ctx.organizationName,
      userId: ctx.userId,
      userName: ctx.userName,
      firstName,
      lastName,
      phoneNumber,
      trainerEmail,
      receiveReview,
      trainingId,
      trainingName,
      airtableRecordId: airtEvalId,
      resumeUrl,
      filename: filename || null,
      interviewStatus: interviewStatus,
    });

    await BackupTrainerEvaluation.create({
      originalId: newEval._id,
      organizationId: newEval.organizationId,
      organizationName: newEval.organizationName,
      userId: newEval.userId,
      userName: newEval.userName,
      firstName: newEval.firstName,
      lastName: newEval.lastName,
      phoneNumber: newEval.phoneNumber,
      trainerEmail: newEval.trainerEmail,
      receiveReview: newEval.receiveReview,
      trainingId: newEval.trainingId,
      trainingName: newEval.trainingName,
      airtableRecordId: newEval.airtableRecordId,
      resumeUrl: newEval.resumeUrl,
      filename: newEval.filename,
      interviewStatus: newEval.interviewStatus,
      transcript: newEval.transcript,
      interviewRecordingUrl: newEval.interviewRecordingUrl,
      callendReason: newEval.callendReason,
      summary: newEval.summary,
      cost: newEval.cost,
      callStartedAt: newEval.callStartedAt,
      callEndedAt: newEval.callEndedAt,
      callId: newEval.callId,
      createdAt: newEval.createdAt,
    });
  } catch (e) {
    console.error("Mongo save error (Trainer Evaluation):", e); // Rollback: Attempt to delete from Airtable if Mongo fails
    if (airtEvalId) {
      console.log(
        `Attempting to delete orphaned Airtable evaluation record: ${airtEvalId}`
      );
      try {
        await axios.delete(
          `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(
            EMP_TABLE
          )}/${airtEvalId}`,
          {
            headers: { Authorization: `Bearer ${AIRTABLE_API_KEY}` },
          }
        );
        console.log(
          `Successfully deleted orphaned Airtable evaluation record: ${airtEvalId}`
        );
      } catch (rollbackError) {
        console.error(
          `Failed to delete orphaned Airtable evaluation record ${airtEvalId}:`,
          rollbackError.response?.data || rollbackError.message
        );
      }
    }
    return res.status(500).send("Database error saving trainer evaluation.");
  }
  res.send("Trainer evaluation submitted successfully!");
});
// --- END MODIFIED CODE ---

// MODIFIED syncEndedInterviews function
async function syncEndedInterviews() {
  console.log("Starting targeted sync for 'pending' MongoDB interviews...");
  let updatedInMongoCount = 0;
  let checkedMongoRecordsCount = 0;

  try {
    const pendingEvaluationsInMongo = await TrainerEvaluation.find({
      interviewStatus: "pending",
      airtableRecordId: { $exists: true, $ne: null, $ne: "" },
    }).lean();

    checkedMongoRecordsCount = pendingEvaluationsInMongo.length;
    if (checkedMongoRecordsCount === 0) {
      console.log(
        "No 'pending' interviews in MongoDB to check against Airtable."
      );
      return {
        updatedCount: 0,
        checkedCount: 0,
        success: true,
        message: "No pending interviews in MongoDB to check.",
      };
    }

    console.log(
      `Found ${checkedMongoRecordsCount} 'pending' interviews in MongoDB to check.`
    );

    const airtableBaseUrl = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(
      EMP_TABLE
    )}`;
    const airtableHeaders = { Authorization: `Bearer ${AIRTABLE_API_KEY}` };
    const recordsToUpdateInMongo = [];
    const backupRecordsToUpdate = [];

    for (const mongoEval of pendingEvaluationsInMongo) {
      if (!mongoEval.airtableRecordId) {
        console.warn(
          `Skipping MongoDB record ID ${mongoEval._id} due to missing airtableRecordId.`
        );
        continue;
      }
      try {
        const airtableRecordUrl = `${airtableBaseUrl}/${mongoEval.airtableRecordId}`;
        const { data: airtableRecord } = await axios.get(airtableRecordUrl, {
          headers: airtableHeaders,
        });

        if (airtableRecord && airtableRecord.fields) {
          const airtableFields = airtableRecord.fields;
          const airtableStatus = airtableFields["Interview Status"];

          if (airtableStatus === "ended") {
            console.log(
              `Airtable record ${mongoEval.airtableRecordId} (Mongo ID: ${mongoEval._id}) is 'ended'. Preparing update for MongoDB.`
            );
            const mongoUpdatePayload = {
              transcript: airtableFields.Transcript || "",
              interviewRecordingUrl:
                airtableFields["Interview Recording"] || "",
              callendReason: airtableFields["Callend Reason"] || "",
              summary: airtableFields.Summary || "",
              cost:
                airtableFields.Cost !== undefined &&
                airtableFields.Cost !== null
                  ? parseFloat(airtableFields.Cost)
                  : 0,
              callStartedAt: airtableFields["Call StartedAt"]
                ? new Date(airtableFields["Call StartedAt"])
                : null,
              callEndedAt: airtableFields["Call EndedAt"]
                ? new Date(airtableFields["Call EndedAt"])
                : null,
              callId: airtableFields["Call ID"] || "",
              interviewStatus: "ended",
            };

            recordsToUpdateInMongo.push({
              updateOne: {
                filter: { airtableRecordId: mongoEval.airtableRecordId },
                update: { $set: mongoUpdatePayload },
              },
            });
            backupRecordsToUpdate.push({
              updateOne: {
                filter: { airtableRecordId: mongoEval.airtableRecordId },
                update: { $set: mongoUpdatePayload },
              },
            });
          } else {
            console.log(
              `Airtable record ${mongoEval.airtableRecordId} (Mongo ID: ${
                mongoEval._id
              }) is still '${
                airtableStatus || "not ended"
              }'. No update needed for this record.`
            );
          }
        } else {
          console.warn(
            `Could not fetch or parse Airtable record for ID: ${mongoEval.airtableRecordId} (Mongo ID: ${mongoEval._id})`
          );
        }
      } catch (airtableError) {
        if (airtableError.response && airtableError.response.status === 404) {
          console.warn(
            `Airtable record not found for ID: ${mongoEval.airtableRecordId} (Mongo ID: ${mongoEval._id}). It might have been deleted from Airtable.`
          );
          recordsToUpdateInMongo.push({
            // Optionally mark as not found in Mongo
            updateOne: {
              filter: { airtableRecordId: mongoEval.airtableRecordId },
              update: {
                $set: { interviewStatus: "airtable_record_not_found" },
              },
            },
          });
          backupRecordsToUpdate.push({
            updateOne: {
              filter: { airtableRecordId: mongoEval.airtableRecordId },
              update: {
                $set: { interviewStatus: "airtable_record_not_found" },
              },
            },
          });
        } else {
          console.error(
            `Error fetching Airtable record ${mongoEval.airtableRecordId} (Mongo ID: ${mongoEval._id}):`,
            airtableError.message
          );
        }
      }
    }

    if (recordsToUpdateInMongo.length > 0) {
      const result = await TrainerEvaluation.bulkWrite(recordsToUpdateInMongo);
      updatedInMongoCount =
        result.modifiedCount || result.matchedCount > 0
          ? recordsToUpdateInMongo.filter(
              (op) =>
                op.updateOne.update.$set.interviewStatus !==
                  "airtable_record_not_found" ||
                op.updateOne.update.$set.interviewStatus === "ended"
            ).length
          : 0; // More accurate count of actual "ended" updates
      console.log(
        `MongoDB bulk update for TrainerEvaluation successful: ${updatedInMongoCount} records potentially updated to ended/not_found.`
      );

      if (backupRecordsToUpdate.length > 0) {
        const backupResult = await BackupTrainerEvaluation.bulkWrite(
          backupRecordsToUpdate
        );
        console.log(
          `MongoDB bulk update for BackupTrainerEvaluation successful: ${backupResult.modifiedCount} backup records potentially updated.`
        );
      }
    } else {
      console.log(
        "No 'pending' MongoDB records found to be 'ended' or 'not_found' in Airtable after checking."
      );
    }
  } catch (error) {
    console.error("Error during syncEndedInterviews:", error);
    return {
      success: false,
      message: error.message || "Sync process failed",
      updatedCount: 0,
      checkedCount: checkedMongoRecordsCount,
    };
  }

  console.log(
    `Sync complete: Checked ${checkedMongoRecordsCount} MongoDB records. Updated/Marked ${updatedInMongoCount} MongoDB records.`
  );
  return {
    success: true,
    message: "Sync process completed.",
    updatedCount: updatedInMongoCount,
    checkedCount: checkedMongoRecordsCount,
  };
}

// MODIFIED this route to await the sync and return results
app.post(
  basePath + "/api/sync-ended-interviews",
  ensureOrgAdminOrSuperAdmin,
  async (req, res) => {
    try {
      const syncResult = await syncEndedInterviews();
      if (syncResult.success) {
        res.json({
          success: true,
          message: syncResult.message,
          checkedCount: syncResult.checkedCount,
          updatedCount: syncResult.updatedCount,
        });
      } else {
        res.status(500).json({
          success: false,
          error: syncResult.message,
          details: syncResult.message,
        });
      }
    } catch (err) {
      console.error("Sync API error during /api/sync-ended-interviews:", err);
      res.status(500).json({
        success: false,
        error: "Sync process failed",
        details: err.message,
      });
    }
  }
);

// --- OTHER ADMIN/MANAGEMENT ROUTES ---
app.get(basePath + "/organizations-dashboard", ensureSuperAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "organizations.html"));
});

app.get(
  basePath + "/manage-users",
  ensureOrgAdminOrSuperAdmin,
  async (req, res) => {
    res.sendFile(path.join(__dirname, "public", "manage-users.html"));
  }
);

// --- STATIC ASSETS (served from 'public' folder, under basePath) ---
app.use(basePath, express.static(path.join(__dirname, "public")));

// Optional: Redirect root path "/" to the application's base path
app.get("/", (req, res) => {
  res.redirect(basePath + "/login");
});

// --- ERROR HANDLING AND 404 ---
app.use(basePath + "/api/*", (req, res) => {
  res.status(404).json({ error: "API endpoint not found." });
});

app.use(basePath + "/*", (req, res, next) => {
  res
    .status(404)
    .sendFile(path.join(__dirname, "public", "404.html"), (err) => {
      if (err) {
        res
          .status(404)
          .send(`Page not found within ${basePath} and 404.html is missing.`);
      }
    });
});

app.use((err, req, res, next) => {
  console.error("Global error handler caught:", err.stack);
  if (!res.headersSent) {
    res.status(err.status || 500).send(err.message || "Something broke!");
  } else {
    next(err);
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}${basePath}`);
  console.log(`Node environment: ${process.env.NODE_ENV || "development"}`);
});
