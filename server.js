import express from "express";
import pkg from "pg";
const { Pool } = pkg;
import cors from "cors";
import * as bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { randomUUID } from "crypto";
import dotenv from "dotenv";

// Load environment variables from .env
dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Supabase PostgreSQL Configuration
const dbPool = new Pool({
  connectionString: process.env.DATABASE_URL, // Use Supabase-provided PostgreSQL URL
  ssl: {
    rejectUnauthorized: false, // Required for cloud-based PostgreSQL like Supabase
  },
});

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

// Login endpoint
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const { rows } = await dbPool.query("SELECT * FROM user_credentials WHERE email = $1", [email]);
    if (rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });

    const isValid = await bcrypt.compare(password, rows[0].password_hash);
    if (!isValid) return res.status(401).json({ error: "Invalid credentials" });

    const { rows: userRows } = await dbPool.query("SELECT * FROM profiles WHERE id = $1", [rows[0].user_id]);
    if (userRows.length === 0) return res.status(404).json({ error: "User profile not found" });

    const token = jwt.sign({ userId: userRows[0].id }, JWT_SECRET, { expiresIn: "24h" });
    res.json({ ...userRows[0], token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Register endpoint
app.post("/api/register", async (req, res) => {
  const { name, email, password, role, rollNumber, department, section, year, designation } = req.body;
  try {
    const userId = randomUUID();
    const hashedPassword = await bcrypt.hash(password, 10);

    const profileQuery = `
      INSERT INTO profiles (id, name, email, role, roll_number, department, section, year, designation, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING *
    `;
    const profileValues = [
      userId,
      name,
      email,
      role,
      rollNumber || null,
      department || null,
      section || null,
      year || null,
      designation || null,
      new Date().toISOString(),
    ];
    const { rows: profileRows } = await dbPool.query(profileQuery, profileValues);

    await dbPool.query("INSERT INTO user_credentials (user_id, email, password_hash) VALUES ($1, $2, $3)", [
      userId,
      email,
      hashedPassword,
    ]);

    const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: "24h" });
    res.json({ ...profileRows[0], token });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Check session endpoint
app.get("/api/check-session", async (req, res) => {
  const token = req.headers.authorization?.split("Bearer ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { rows } = await dbPool.query("SELECT * FROM profiles WHERE id = $1", [decoded.userId]);
    if (rows.length === 0) return res.status(404).json({ error: "User not found" });
    res.json(rows[0]);
  } catch (error) {
    console.error("Session check error:", error);
    res.status(401).json({ error: "Invalid token" });
  }
});

// Update profile endpoint
app.put("/api/update-profile", async (req, res) => {
  const token = req.headers.authorization?.split("Bearer ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { name, email, rollNumber, department, section, year, designation } = req.body;

    const query = `
      UPDATE profiles 
      SET 
        name = COALESCE($1, name),
        email = COALESCE($2, email),
        roll_number = COALESCE($3, roll_number),
        department = COALESCE($4, department),
        section = COALESCE($5, section),
        year = COALESCE($6, year),
        designation = COALESCE($7, designation)
      WHERE id = $8
      RETURNING *
    `;
    const values = [
      name || null,
      email || null,
      rollNumber || null,
      department || null,
      section || null,
      year || null,
      designation || null,
      decoded.userId,
    ];
    const { rows } = await dbPool.query(query, values);

    if (rows.length === 0) return res.status(404).json({ error: "User not found" });
    res.json(rows[0]);
  } catch (error) {
    console.error("Update profile error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Fetch all sessions for the user
app.get("/api/sessions", async (req, res) => {
  const token = req.headers.authorization?.split("Bearer ")[1];
  if (!token) {
    console.error("No token provided in request headers");
    return res.status(401).json({ error: "No token provided" });
  }

  try {
    console.log("Received token for sessions:", token);
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log("Decoded token:", decoded);

    // Fetch the user's roll_number from profiles
    const profileQuery = "SELECT roll_number FROM profiles WHERE id = $1";
    const { rows: profileRows } = await dbPool.query(profileQuery, [decoded.userId]);
    if (profileRows.length === 0) {
      console.error("User profile not found for ID:", decoded.userId);
      return res.status(404).json({ error: "User profile not found" });
    }
    const rollNumber = profileRows[0].roll_number || null;
    console.log("User roll_number:", rollNumber);

    const query = `
      SELECT gs.*, 
             array_agg(DISTINCT gp.student_id) as participants,
             array_agg(DISTINCT ge.evaluator_id) as evaluators
      FROM gd_sessions gs
      LEFT JOIN gd_participants gp ON gs.id = gp.gd_session_id
      LEFT JOIN gd_evaluators ge ON gs.id = ge.gd_session_id
      WHERE gs.created_by = $1 
         OR gp.student_id = $2 
         OR ge.evaluator_id = $2
      GROUP BY gs.id
    `;
    console.log("Executing sessions query with userId:", decoded.userId, "and rollNumber:", rollNumber);
    const { rows } = await dbPool.query(query, [decoded.userId, rollNumber]);
    console.log("Sessions query result:", rows);
    res.json(rows);
  } catch (error) {
    console.error("Fetch sessions error:", error.message, error.stack);
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
    if (error.code === "ECONNREFUSED" || error.code === "28P01") {
      return res.status(500).json({ error: "Database connection failed" });
    }
    res.status(500).json({ error: "Server error", details: error.message });
  }
});

// Create a GD session
app.post("/api/create-session", async (req, res) => {
  const token = req.headers.authorization?.split("Bearer ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { topic, details, groupName, groupNumber, date, participants, evaluators } = req.body;

    if (!topic || !details || !groupName || !groupNumber || !date) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const sessionId = randomUUID();
    const sessionQuery = `
      INSERT INTO gd_sessions (id, topic, details, group_name, group_number, date, created_by, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `;
    const sessionValues = [
      sessionId,
      topic,
      details,
      groupName,
      groupNumber,
      date,
      decoded.userId,
      new Date().toISOString(),
    ];
    const { rows: sessionRows } = await dbPool.query(sessionQuery, sessionValues);

    // Insert participants
    if (participants && participants.length > 0) {
      const participantValues = participants.map((studentId) => [randomUUID(), sessionId, String(studentId)]);
      const placeholders = participantValues.map((_, i) => `($${i * 3 + 1}, $${i * 3 + 2}, $${i * 3 + 3})`).join(", ");
      const query = `INSERT INTO gd_participants (id, gd_session_id, student_id) VALUES ${placeholders}`;
      await dbPool.query(query, participantValues.flat());
    }

    // Insert evaluators
    if (evaluators && evaluators.length > 0) {
      const evaluatorValues = evaluators.map((evaluatorId) => [randomUUID(), sessionId, String(evaluatorId)]);
      const placeholders = evaluatorValues.map((_, i) => `($${i * 3 + 1}, $${i * 3 + 2}, $${i * 3 + 3})`).join(", ");
      const query = `INSERT INTO gd_evaluators (id, gd_session_id, evaluator_id) VALUES ${placeholders}`;
      await dbPool.query(query, evaluatorValues.flat());
    }

    // Fetch the complete session with participants and evaluators
    const completeSessionQuery = `
      SELECT gs.*, 
             array_agg(DISTINCT gp.student_id) as participants,
             array_agg(DISTINCT ge.evaluator_id) as evaluators
      FROM gd_sessions gs
      LEFT JOIN gd_participants gp ON gs.id = gp.gd_session_id
      LEFT JOIN gd_evaluators ge ON gs.id = ge.gd_session_id
      WHERE gs.id = $1
      GROUP BY gs.id
    `;
    const { rows } = await dbPool.query(completeSessionQuery, [sessionId]);
    res.json(rows[0]);
  } catch (error) {
    console.error("Create session error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Fetch all evaluations
app.get("/api/evaluations", async (req, res) => {
  const token = req.headers.authorization?.split("Bearer ")[1];
  if (!token) {
    console.error("No token provided in request headers");
    return res.status(401).json({ error: "No token provided" });
  }

  try {
    console.log("Received token for evaluations:", token);
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log("Decoded token:", decoded);

    // Check if the user is an instructor
    const profileQuery = "SELECT role FROM profiles WHERE id = $1";
    const { rows: profileRows } = await dbPool.query(profileQuery, [decoded.userId]);
    if (profileRows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }
    const isInstructor = profileRows[0].role === "instructor";

    let query;
    if (isInstructor) {
      // Fetch all evaluations for sessions created by the instructor
      query = `
        SELECT e.*
        FROM evaluations e
        JOIN gd_sessions gs ON e.gd_session_id = gs.id
        WHERE gs.created_by = $1
      `;
    } else {
      // Fetch evaluations where user is evaluator or student
      query = `
        SELECT * 
        FROM evaluations 
        WHERE evaluator_id = $1 
           OR student_id = CAST($1 AS VARCHAR)
      `;
    }

    console.log("Executing evaluations query with userId:", decoded.userId);
    const { rows } = await dbPool.query(query, [decoded.userId]);
    console.log("Evaluations query result:", rows);
    res.json(rows);
  } catch (error) {
    console.error("Fetch evaluations error:", error.message, error.stack);
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
    if (error.code === "ECONNREFUSED" || error.code === "28P01") {
      return res.status(500).json({ error: "Database connection failed" });
    }
    res.status(500).json({ error: "Server error", details: error.message });
  }
});

// Submit an evaluation
app.post("/api/submit-evaluation", async (req, res) => {
  const token = req.headers.authorization?.split("Bearer ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { gdSessionId, studentId, criteria } = req.body;

    if (!gdSessionId || !studentId || !criteria) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    console.log("Submitting evaluation for session:", gdSessionId, "by user:", decoded.userId);

    const sessionQuery = "SELECT * FROM gd_sessions WHERE id = $1";
    const { rows: sessionRows } = await dbPool.query(sessionQuery, [gdSessionId]);
    if (sessionRows.length === 0) return res.status(404).json({ error: "Session not found" });

    const participantQuery = "SELECT * FROM gd_participants WHERE gd_session_id = $1 AND student_id = $2";
    const { rows: participantRows } = await dbPool.query(participantQuery, [gdSessionId, studentId]);
    if (participantRows.length === 0) return res.status(400).json({ error: "Student is not a participant" });

    // Fetch the user's roll_number from profiles
    const profileQuery = "SELECT roll_number FROM profiles WHERE id = $1";
    const { rows: profileRows } = await dbPool.query(profileQuery, [decoded.userId]);
    if (profileRows.length === 0) {
      console.error("User profile not found for ID:", decoded.userId);
      return res.status(404).json({ error: "User profile not found" });
    }
    const rollNumber = profileRows[0].roll_number || null;
    console.log("Evaluator roll_number:", rollNumber);

    const evaluatorQuery = "SELECT * FROM gd_evaluators WHERE gd_session_id = $1 AND evaluator_id = $2";
    const { rows: evaluatorRows } = await dbPool.query(evaluatorQuery, [gdSessionId, rollNumber]);
    const isInstructor = sessionRows[0].created_by === decoded.userId;
    console.log("Is instructor:", isInstructor, "Evaluator rows:", evaluatorRows);

    if (!isInstructor && evaluatorRows.length === 0) {
      console.error("User not authorized: not instructor and not in evaluators list");
      return res.status(403).json({ error: "Not authorized to evaluate this session" });
    }

    const evaluationId = randomUUID();
    const query = `
      INSERT INTO evaluations (id, gd_session_id, student_id, evaluator_id, articulation, relevance, leadership, non_verbal_communication, impression, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      ON CONFLICT (gd_session_id, student_id, evaluator_id)
      DO UPDATE SET 
        articulation = $5, relevance = $6, leadership = $7, non_verbal_communication = $8, impression = $9, created_at = $10
      RETURNING *
    `;
    const values = [
      evaluationId,
      gdSessionId,
      studentId,
      decoded.userId,
      criteria.articulation,
      criteria.relevance,
      criteria.leadership,
      criteria.nonVerbalCommunication,
      criteria.impression,
      new Date().toISOString(),
    ];
    const { rows } = await dbPool.query(query, values);
    console.log("Evaluation submitted:", rows[0]);
    res.json(rows[0]);
  } catch (error) {
    console.error("Submit evaluation error:", error.message, error.stack);
    res.status(500).json({ error: "Server error", details: error.message });
  }
});

app.listen(3001, () => console.log("Server running on port 3001"));