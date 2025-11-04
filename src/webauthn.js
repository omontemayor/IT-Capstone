require('dotenv').config();
const express = require('express');
const router = express.Router();
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const base64url = require('base64url');
const cookieSession = require('cookie-session');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

router.use(cookieSession({
  name: 'webauthn-session',
  keys: [process.env.SESSION_KEY || 'replace_me'],
  maxAge: 24 * 60 * 60 * 1000,
}));

const rpName = 'IT-Capstone';
const rpID = 'localhost';
const origin = 'http://localhost:3000';

// --- Register: start
router.post('/register/options', async (req, res) => {
  const { email, name } = req.body;
  if (!email) return res.status(400).json({ error: 'Missing email' });
  let user = await prisma.user.findUnique({ where: { email } });
  if (!user) user = await prisma.user.create({ data: { email, name } });

  const options = generateRegistrationOptions({
    rpName,
    rpID,
    userID: String(user.id),
    userName: email,
  });

  req.session.challenge = options.challenge;
  req.session.userId = user.id;
  res.json(options);
});

// --- Register: verify
router.post('/register/verify', async (req, res) => {
  const expectedChallenge = req.session.challenge;
  const userId = req.session.userId;

  try {
    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (!verification.verified) return res.status(400).json({ error: 'Failed' });

    const { credentialPublicKey, credentialID, counter } = verification.registrationInfo;
    await prisma.credential.create({
      data: {
        credentialId: base64url.encode(credentialID),
        userId,
        publicKey: Buffer.from(credentialPublicKey).toString('base64'),
        counter,
      },
    });

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error verifying' });
  }
});

// --- Authenticate: start
router.post('/authenticate/options', async (req, res) => {
  const { email } = req.body;
  const user = await prisma.user.findUnique({ where: { email }, include: { credentials: true } });
  if (!user) return res.status(404).json({ error: 'User not found' });

  const options = generateAuthenticationOptions({
    rpID,
    allowCredentials: user.credentials.map(c => ({
      id: base64url.toBuffer(c.credentialId),
      type: 'public-key',
    })),
  });

  req.session.challenge = options.challenge;
  req.session.userId = user.id;
  res.json(options);
});

// --- Authenticate: verify
router.post('/authenticate/verify', async (req, res) => {
  const expectedChallenge = req.session.challenge;
  const user = await prisma.user.findUnique({
    where: { id: req.session.userId },
    include: { credentials: true },
  });

  const cred = user.credentials.find(c => c.credentialId === base64url.encode(Buffer.from(req.body.id)));
  if (!cred) return res.status(400).json({ error: 'Unknown credential' });

  const verification = await verifyAuthenticationResponse({
    response: req.body,
    expectedChallenge,
    expectedOrigin: origin,
    expectedRPID: rpID,
    authenticator: {
      credentialPublicKey: Buffer.from(cred.publicKey, 'base64'),
      credentialID: base64url.toBuffer(cred.credentialId),
      counter: cred.counter,
    },
  });

  if (!verification.verified) return res.status(400).json({ error: 'Verification failed' });

  await prisma.credential.update({
    where: { id: cred.id },
    data: { counter: verification.authenticationInfo.newCounter },
  });

  res.json({ ok: true });
});

module.exports = router;

const QRCode = require('qrcode');

// --- Generate QR code for a student
router.get('/student/:id/qrcode', async (req, res) => {
  const studentId = req.params.id;

  // For demonstration: use a signed token (you could replace with JWT)
  const validationToken = Buffer.from(`student:${studentId}:${Date.now()}`).toString('base64');

  // Generate QR code
  try {
    const qrDataURL = await QRCode.toDataURL(validationToken);
    res.json({ qr: qrDataURL, token: validationToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'QR code generation failed' });
  }
});

// --- Validate QR code token
router.post('/student/validate', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Missing token' });

  try {
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    const [prefix, studentId, timestamp] = decoded.split(':');

    if (prefix !== 'student') return res.status(400).json({ error: 'Invalid token' });

    // Optional: Check if token is too old (e.g., 5 minutes)
    if (Date.now() - parseInt(timestamp) > 5 * 60 * 1000) {
      return res.status(400).json({ error: 'Token expired' });
    }

    res.json({ ok: true, studentId });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Invalid token format' });
  }
});

