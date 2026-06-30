require("dotenv").config();

const app = require("./src/app");
const connectDB = require("./src/config/db");
const User = require("./src/models/User");
const { execSync } = require("child_process");

const seedAdmin = async () => {
  try {
    const existing = await User.findOne({ email: "admin@merkato.com" });
    if (!existing) {
      await User.create({
        firstName: "Admin",
        lastName: "User",
        email: "admin@merkato.com",
        password: "Admin123",
        role: "admin",
        isVerified: true,
      });
      console.log("👑 Admin user seeded (admin@merkato.com / Admin123)");
    }
  } catch (err) {
    console.error("Admin seed error:", err.message);
  }
};

const startServer = async () => {
  await connectDB();
  await seedAdmin();

  const PORT = process.env.PORT || 5000;
  const NODE_ENV = process.env.NODE_ENV || "development";

  const listen = () => {
    const server = app.listen(PORT, () => {
      console.log(`==================================================`);
      console.log(` 🛡️  Merkato Security Engine Active`);
      console.log(` 🚀 Server Listening on Port: ${PORT}`);
      console.log(` ⚙️  Environment Mode: ${NODE_ENV}`);
      console.log(`==================================================`);
    });

    server.on("error", (err) => {
      if (err.code === "EADDRINUSE") {
        console.error(`⚠️  Port ${PORT} is in use. Attempting to free it...`);
        try {
          const result = execSync(
            `netstat -ano | findstr :${PORT}`,
            { encoding: "utf8", timeout: 5000 },
          );
          const lines = result.trim().split("\n");
          for (const line of lines) {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 5 && parts[1] === `0.0.0.0:${PORT}`) {
              const pid = parts[parts.length - 1];
              execSync(`taskkill /F /PID ${pid}`, { timeout: 3000 });
              console.log(`✅ Killed process ${pid}. Restarting on port ${PORT}...`);
              break;
            }
          }
        } catch (killErr) {
          console.error("❌ Could not auto-free the port. Manually run:");
          console.error(`   netstat -ano | findstr :${PORT}`);
          console.error("   then: taskkill /F /PID <PID>");
          return process.exit(1);
        }
        server.close();
        setTimeout(listen, 1000);
      }
    });

    process.on("unhandledRejection", (err) => {
      console.error(`💥 CRITICAL: Unhandled Promise Rejection: ${err.message}`);
      server.close(() => {
        process.exit(1);
      });
    });
  };

  listen();
};

startServer();
