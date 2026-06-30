const express = require("express");
const router = express.Router();
const {
  register,
  verifyEmail,
  login,
  googleAuth,
  forgotPassword,
  resetPassword,
  updateProfile,
} = require("../controllers/authController");
const { protect } = require("../middlewares/authMiddleware");
const upload = require("../middlewares/uploadMiddleware");

// Public Routes (No authentication required)
router.post("/register", register);
router.get("/verify-email", verifyEmail);
router.post("/login", login);
router.post("/google", googleAuth);
router.post("/forgot-password", forgotPassword);
router.put("/reset-password/:token", resetPassword);

// Protected Routes (Require a valid JWT access token)
router.put("/profile", protect, upload.single("avatar"), updateProfile);
router.get("/me", protect, (req, res) => {
  res.status(200).json({
    success: true,
    user: req.user,
  });
});

module.exports = router;
