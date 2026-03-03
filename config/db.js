// config/db.js
// Handles MongoDB Atlas connection using Mongoose.
// Kept separate from server.js so connection logic is reusable and testable.

const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI);

    console.log(`✅ MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(`❌ MongoDB Connection Failed: ${error.message}`);
    // Exit process with failure code — app cannot run without DB
    process.exit(1);
  }
};

module.exports = connectDB;
