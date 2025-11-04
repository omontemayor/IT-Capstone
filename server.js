require('dotenv').config();
const express = require('express');
const app = express();
const webauthnRoutes = require('./src/webauthn');
app.use(express.json());
app.use('/webauthn', webauthnRoutes);

app.listen(3000, () => console.log('✅ Server running on http://localhost:3000'));

