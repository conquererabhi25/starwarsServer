const mongoose = require("mongoose");

const userModel = new mongoose.Schema({
    name: String,
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
});

const User = mongoose.model("users", userModel);

module.exports = User;
