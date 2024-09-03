const { users, User } = require("./user");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const express = require("express");
const app = express();

app.use(express.json());
app.use(express.static("public"));
app.listen(3002, () => {
  console.log("Server started on port 3002");
});

app.post("/register", (req, res) => {
  const { name, email, password } = req.body;
  // Generate a new secret key for the user
  const secret = speakeasy.generateSecret({ length: 20 });
  // Save the user data in the database
  const user = new User(users.length + 1, name, email, password, secret.base32);
  users.push(user);
  // Generate a QR code for the user to scan
  QRCode.toDataURL(secret.otpauth_url, (err, image_data) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Internal Server Error");
    }
    // Send the QR code to the user
    res.send({ qrCode: image_data });
  });
});

app.post("/login", (req, res) => {
  const { email, password, token } = req.body;
  // Find the user with the given email address
  const user = users.find((u) => u.email === email);
  // Validate the user's credentials
  if (!user || user.password !== password) {
    return res.status(401).send("Invalid credentials");
  }
  // Verify the user's token
  const verified = speakeasy.totp.verify({
    secret: user.secret,
    encoding: "base32",
    token,
    window: 1,
  });
  if (!verified) {
    return res.status(401).send("Invalid token");
  }
  // User is authenticated
  res.send("Login successful");
});

const requireToken = (req, res, next) => {
  const { token } = req.body;
  // Find the user with the given email address
  const user = users.find((u) => u.email === req.user.email);
  // Verify the user's token
  const verified = speakeasy.totp.verify({
    secret: user.secret,
    encoding: "base32",
    token,
    window: 1,
  });
  if (!verified) {
    return res.status(401).send("Invalid token");
  }
  // Token is valid, proceed to the next middleware or route handler
  next();
};

app.post("/protected", requireToken, (req, res) => {
  // This route handler will only be called if the user's token is valid
  res.send("Protected resource accessed successfully");
});
