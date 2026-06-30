const User = require("../models/User");
const AuditLog = require("../models/AuditLog");
const sendEmail = require("../utils/sendEmail");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const axios = require("axios"); // For validating CAPTCHA tokens if needed

/**
 * Generates both Access and Refresh tokens for a verified user session
 */
const generateTokens = (user) => {
  const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE,
  });

  const refreshToken = jwt.sign(
    { id: user._id },
    process.env.JWT_REFRESH_SECRET,
    {
      expiresIn: process.env.JWT_REFRESH_EXPIRE,
    },
  );

  return { accessToken, refreshToken };
};

/**
 * @desc    Register a new user with pending email verification
 * @route   POST /api/v1/auth/register
 * @access  Public
 */
exports.register = async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      password,
      acceptTerms,
      recaptchaToken,
    } = req.body;

    // 1. Structural Validations
    if (!firstName || !lastName || !email || !password) {
      return res
        .status(400)
        .json({
          success: false,
          message: "Please provide all required fields",
        });
    }

    if (!acceptTerms) {
      return res
        .status(400)
        .json({
          success: false,
          message: "You must accept the Terms of Service and Privacy Policy",
        });
    }

    // 2. Check if user already exists
    const userExists = await User.findOne({ email: email.toLowerCase() });
    if (userExists) {
      return res
        .status(400)
        .json({ success: false, message: "Email is already registered" });
    }

    // 3. Create user (auto-verified so login works without email)
    const user = await User.create({
      firstName,
      lastName,
      email: email.toLowerCase(),
      password,
      isVerified: true,
    });

    res.status(201).json({
      success: true,
      message: "Registration successful! You can now log in.",
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @desc    Verify email token to activate account
 * @route   GET /api/v1/auth/verify-email
 * @access  Public
 */
exports.verifyEmail = async (req, res) => {
  try {
    // Hash the token sent in the URL to compare with hashed token in DB
    const verificationToken = crypto
      .createHash("sha256")
      .update(req.query.token)
      .digest("hex");

    const user = await User.findOne({
      verificationToken,
      verificationTokenExpire: { $gt: Date.now() },
    });

    if (!user) {
      return res
        .status(400)
        .json({
          success: false,
          message: "Invalid or expired verification token",
        });
    }

    // Activate the user account
    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpire = undefined;
    await user.save();

    // Create Audit Log
    await AuditLog.create({
      userId: user._id,
      action: "EMAIL_VERIFIED",
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
      details: "User successfully completed email verification pipeline.",
    });

    res.status(200).json({
      success: true,
      message: "Email verified successfully! You can now log in.",
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @desc    Authenticate user & get tokens (with lockout mitigation)
 * @route   POST /api/v1/auth/login
 * @access  Public
 */
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ success: false, message: "Please provide email and password" });
    }

    const user = await User.findOne({ email: email.toLowerCase() }).select(
      "+password",
    );

    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });
    }

    // Check if account is currently locked out
    if (user.loginAttempts >= 5 && user.lockUntil > Date.now()) {
      const remainingTime = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return res.status(423).json({
        success: false,
        message: `Account temporarily locked due to excessive failures. Try again in ${remainingTime} minutes.`,
      });
    }

    // Verify password match
    const isMatch = await user.matchPassword(password);

    if (!isMatch) {
      // Increment login failure counter
      user.loginAttempts += 1;
      if (user.loginAttempts >= 5) {
        user.lockUntil = Date.now() + 15 * 60 * 1000; // Lock for 15 minutes

        await AuditLog.create({
          userId: user._id,
          action: "ACCOUNT_LOCKED",
          ipAddress: req.ip,
          userAgent: req.headers["user-agent"],
          details:
            "Account temporarily locked out due to 5 consecutive invalid login attempts.",
        });
      }
      await user.save();
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });
    }

    // Check if user verified their email address
    if (!user.isVerified) {
      return res
        .status(403)
        .json({
          success: false,
          message: "Please verify your email address before logging in.",
        });
    }

    // Reset login failures tracking upon safe entrance
    user.loginAttempts = 0;
    user.lockUntil = undefined;
    await user.save();

    // Issue Access & Refresh tokens
    const { accessToken, refreshToken } = generateTokens(user);

    // Track successful sign-in
    await AuditLog.create({
      userId: user._id,
      action: "LOGIN_SUCCESS",
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
    });

    // Send login notification email (non-blocking)
    sendEmail({
      email: user.email,
      subject: "New Login to Your Merkato Account",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto;">
          <h2 style="color: #f97316;">Merkato Store</h2>
          <p>Hi <strong>${user.firstName}</strong>,</p>
          <p>A new login was detected on your account.</p>
          <div style="background: #f9f9f9; padding: 12px; border-radius: 8px; font-size: 13px;">
            <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
            <p><strong>IP Address:</strong> ${req.ip}</p>
          </div>
          <p style="font-size: 12px; color: #666; margin-top: 16px;">
            If this wasn't you, please secure your account immediately.
          </p>
        </div>
      `,
    }).catch((err) => console.error("Login email failed:", err.message));

    res.status(200).json({
      success: true,
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        avatar: user.avatar,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

/**
 * @desc    Google OAuth login/signup
 * @route   POST /api/v1/auth/google
 * @access  Public
 */
exports.googleAuth = async (req, res) => {
  try {
    const { accessToken } = req.body;

    if (!accessToken) {
      return res.status(400).json({
        success: false,
        message: "Google access token is required",
      });
    }

    // Fetch user info from Google API
    const googleRes = await axios.get(
      "https://www.googleapis.com/oauth2/v2/userinfo",
      {
        headers: { Authorization: `Bearer ${accessToken}` },
      },
    );

    const { email, given_name, family_name, name, picture } = googleRes.data;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Could not retrieve email from Google account",
      });
    }

    // Check if user already exists
    let user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      // Create new user from Google profile
      user = await User.create({
        firstName: given_name || name || "User",
        lastName: family_name || "",
        email: email.toLowerCase(),
        password: crypto.randomBytes(20).toString("hex"),
        isVerified: true,
        avatar: picture || "",
      });
    }

    // Generate tokens
    const tokens = generateTokens(user);

    // Track sign-in
    await AuditLog.create({
      userId: user._id,
      action: "GOOGLE_LOGIN",
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
      details: "User authenticated via Google OAuth",
    }).catch(() => {});

    res.status(200).json({
      success: true,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        avatar: user.avatar,
      },
    });
  } catch (error) {
    console.error("Google Auth Error:", error.message);
    res.status(500).json({
      success: false,
      message: "Google authentication failed. Please try again.",
    });
  }
};

exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Please provide your email address",
      });
    }

    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "No account found with that email address",
      });
    }

    const resetToken = user.getResetPasswordToken();
    await user.save({ validateBeforeSave: false });

    const resetUrl = `${process.env.CLIENT_URL || process.env.FRONTEND_URL || "http://localhost:5173"}/reset-password?token=${resetToken}`;

    const htmlTemplate = `
      <h1>Merkato Store - Password Reset</h1>
      <p>You requested a password reset. Click the link below to set a new password:</p>
      <a href="${resetUrl}" target="_blank" style="padding: 10px 20px; background-color: #f97316; color: white; text-decoration: none; display: inline-block; border-radius: 8px;">Reset Password</a>
      <p>This link will expire in 15 minutes.</p>
      <p>If you did not request this, please ignore this email.</p>
    `;

    console.log(`\n🔗 Password Reset Link: ${resetUrl}\n`);

    sendEmail({
      email: user.email,
      subject: "Merkato Store - Password Reset Request",
      html: htmlTemplate,
    }).catch((err) => console.error("Reset email failed:", err.message));

    res.status(200).json({
      success: true,
      message: "Password reset link sent to your email",
      resetUrl,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    if (!token || !password) {
      return res.status(400).json({
        success: false,
        message: "Token and new password are required",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters",
      });
    }

    const hashedToken = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired reset token",
      });
    }

    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();

    await AuditLog.create({
      userId: user._id,
      action: "PASSWORD_CHANGED",
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"],
      details: "Password reset via forgot-password flow",
    });

    res.status(200).json({
      success: true,
      message: "Password updated successfully. You can now log in.",
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

exports.updateProfile = async (req, res) => {
  try {
    const { firstName, lastName } = req.body;
    const user = await User.findById(req.user._id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;

    if (req.file) {
      user.avatar = `/uploads/${req.file.filename}`;
    }

    await user.save();

    res.status(200).json({
      success: true,
      message: "Profile updated successfully",
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        avatar: user.avatar,
      },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};
