const express = require("express");
const crypto = require("node:crypto");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

if (!globalThis.crypto) {
  globalThis.crypto = crypto;
}

const PORT = process.env.PORT || 3000;
const app = express();

app.use(express.static("./public"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const userStore = {};
const challengeStore = {};

app.post("/register", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send("Username and password are required");
  }

  if (userStore[username]) {
    return res.status(400).send("Username already exists");
  }

  const id = `user_${Date.now()}`;

  const user = {
    id,
    username,
    password,
  };

  userStore[id] = user;

  res.status(201).json({ id });
});

app.post("/register-passkey", async (req, res) => {
  const { userId } = req.body;

  if (!userStore[userId])
    return res.status(404).json({ error: "User not found" });

  const user = userStore[userId];

  const challengePayload = await generateRegistrationOptions({
    rpID: "localhost",
    rpName: "SimpleWebAuthn",
    userName: user.username,
  });

  challengeStore[userId] = challengePayload.challenge;

  res.json({ options: challengePayload });
});

app.post("/verify-passkey", async (req, res) => {
  const { userId, cred } = req.body;

  if (!userStore[userId])
    return res.status(404).json({ error: "User not found" });

  const user = userStore[userId];
  const challenge = challengeStore[userId];

  const verificationResult = await verifyRegistrationResponse({
    expectedChallenge: challenge,
    expectedOrigin: "http://localhost:3000",
    expectedRPID: "localhost",
    response: cred,
  });

  if (!verificationResult.verified) {
    return res.status(400).json({ error: "Verification failed" });
  }

  userStore[userId].passkey = verificationResult.registrationInfo;

  res.json({ success: true });
});

app.post("/login-passkey", async (req, res) => {
  const { userId } = req.body;

  if (!userStore[userId])
    return res.status(404).json({ error: "User not found" });

  const opts = await generateAuthenticationOptions({
    rpID: "localhost",
  });

  challengeStore[userId] = opts.challenge;

  res.json({ options: opts });
});

app.post("/verify-login-passkey", async (req, res) => {
  const { userId, cred } = req.body;

  if (!userStore[userId])
    return res.status(404).json({ error: "User not found" });

  const user = userStore[userId];
  const challenge = challengeStore[userId];

  const result = await verifyAuthenticationResponse({
    expectedChallenge: challenge,
    expectedOrigin: "http://localhost:3000",
    expectedRPID: "localhost",
    response: cred,
    authenticator: user.passkey,
  });

  if (!result.verified) {
    return res.status(400).json({ error: "Verification failed" });
  }

  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
