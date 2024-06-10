const express = require("express");
const app = express();
require('dotenv').config();
const cors = require("cors");
require("./StarWarsDB/connection");
const users = require("./StarWarsDB/UserModel");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const Jwt = require("jsonwebtoken");
const jwtkey = "alpha";

app.use(express.json());
app.use(cors());

app.get("/", (req, res) => {
  res.send("working");
});

// SIGN UP API
app.post("/signup", async (req, res) => {
  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);
    let user = new users({ ...req.body, password: hashedPassword });
    let result = await user.save();
    result = result.toObject();
    delete result.password; // this is intentionally done to keep password hidden.
    res.send(result);
  } catch (error) {
    if (error.code === 11000) {
      res.status(400).send({ error: "Email already exists." });
    } else {
      res.status(500).send({ error: "Something went wrong. Please try again later." });
    }
  }
});

// LOGIN API
app.post("/login", async (req, resp) => {
  if (req.body.password && req.body.email) {
    const user = await users.findOne({ email: req.body.email });
    if (user && await bcrypt.compare(req.body.password, user.password)) {
      const userdata = { email: user.email, name: user.name };
      Jwt.sign({ userdata }, jwtkey, { expiresIn: "24h" }, (err, token) => {
        if (err) {
          resp.send({ result: "Something went wrong, please try after sometime" });
        }
        resp.send({ userdata, auth: token });
      });
    } else {
      resp.send({ result: "Invalid credentials" });
    }
  } else {
    resp.send({ result: "Please provide email and password" });
  }
});

// FORGOT PASSWORD API
app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    const user = await users.findOne({ email });
    if (!user) return res.status(400).send("User with that email does not exist.");

    const token = crypto.randomBytes(20).toString("hex");
    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

    await user.save();

    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      to: user.email,
      from: process.env.EMAIL_USER,
      subject: "Password Reset",
      text: `You are receiving this because you (or someone else) have requested to reset the password for your account.\n\n
             Please click on the following link, or paste this into your browser to complete the process:\n\n
             https://starwars-client.onrender.com/reset-password/${token}
             If you did not request this, please ignore this email and your password will remain unchanged.\n`,
    };

    transporter.sendMail(mailOptions, (err, response) => {
      if (err) {
        console.error("Error sending email: ", err);
        return res.status(500).send("Error sending email.");
      } else {
        console.log("Email sent: ", response);
        return res.send("Password reset link has been sent to your email. Reset Password and come back to Login");
      }
    });
  } catch (err) {
    console.error("Error on the server: ", err);
    res.status(500).send("Error on the server.");
  }
});


// RESET PASSWORD API
app.post("/reset-password/:token", async (req, res) => {
  try {
    const user = await users.findOne({
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) return res.status(400).send("Password reset token is invalid or has expired.");

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    await user.save();

    res.send("Password has been reset.Please go back to login Page");
  } catch (err) {
    res.status(500).send("Error on the server.");
  }
});


app.listen(5000, () => {
  console.log("Server is running on port 5000");
});
