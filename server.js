const express = require("express");
const cookieParser = require("cookie-parser");

const requestLogger = require("./middleware/logger");
const authMiddleware = require("./middleware/auth");
const { generateToken } = require("./utils/tokenGenerator");
require("dotenv").config();


const app = express();
const PORT = process.env.PORT || 3000;

// In-memory storage
const loginSessions = {};
const otpStore = {};

app.use(requestLogger);
app.use(express.json());
app.use(cookieParser());

app.get("/", (req, res) => {
  res.json({ message: "Authentication Flow API Running" });
});

/* ============================
   STEP 1 - LOGIN
============================ */
app.post("/auth/login", (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password required",
      });
    }

    // Generate session ID
    const loginSessionId = Math.random().toString(36).substring(2, 10);

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000);

    // Store session
    loginSessions[loginSessionId] = {
      email,
      createdAt: Date.now(),
      expiresAt: Date.now() + 2 * 60 * 1000, // 2 minutes
    };

    // Store OTP
    otpStore[loginSessionId] = otp;

    // 🔥 PRINT OTP CLEARLY
    console.log("================================");
    console.log("NEW LOGIN REQUEST");
    console.log("Email:", email);
    console.log("Session ID:", loginSessionId);
    console.log("OTP:", otp);
    console.log("================================");

    return res.status(200).json({
      message: "OTP generated successfully",
      loginSessionId,
      otp, // keep this for testing (remove in production)
    });

  } catch (error) {
    return res.status(500).json({
      error: "Login failed",
    });
  }
});

/* ============================
   STEP 2 - VERIFY OTP
============================ */
app.post("/auth/verify-otp", (req, res) => {
  try {
    const { loginSessionId, otp } = req.body;

    if (!loginSessionId || !otp) {
      return res.status(400).json({
        error: "loginSessionId and otp required",
      });
    }

    const session = loginSessions[loginSessionId];

    if (!session) {
      return res.status(401).json({
        error: "Invalid session",
      });
    }

    if (Date.now() > session.expiresAt) {
      delete loginSessions[loginSessionId];
      delete otpStore[loginSessionId];

      return res.status(401).json({
        error: "Session expired",
      });
    }

    if (parseInt(otp) !== otpStore[loginSessionId]) {
      return res.status(401).json({
        error: "Invalid OTP",
      });
    }

    delete otpStore[loginSessionId];

    res.cookie("session_token", loginSessionId, {
      httpOnly: true,
      maxAge: 15 * 60 * 1000,
    });

    return res.status(200).json({
      message: "OTP verified successfully",
    });

  } catch (error) {
    return res.status(500).json({
      error: "OTP verification failed",
    });
  }
});

/* ============================
   STEP 3 - GENERATE JWT TOKEN
============================ */
app.post("/auth/token", async(req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({
        error: "Authorization header missing",
      });
    }

    const sessionId = authHeader.replace("Bearer ", "");
    const session = loginSessions[sessionId];

    if (!session) {
      return res.status(401).json({
        error: "Invalid session",
      });
    }

    const accessToken = await generateToken({
      email: session.email,
      sessionId,
    });

    return res.status(200).json({
      access_token: accessToken,
      expires_in: 900,
    });

  } catch (error) {
    return res.status(500).json({
      error: "Token generation failed",
    });
  }
});

/* ============================
   PROTECTED ROUTE
============================ */
app.get("/protected", authMiddleware, (req, res) => {
  return res.json({
    message: "Access granted",
    user: req.user,
    success_flag: `FLAG-${Buffer.from(
      req.user.email + "_COMPLETED_ASSIGNMENT"
    ).toString("base64")}`,
  });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
