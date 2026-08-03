const express = require('express');
const path = require('path');

const app = express();

// Serve all files in the workspace root (including email_blast.html)
app.use(express.static(path.join(__dirname)));

// Serve the email blast as the homepage
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'email_blast.html'));
});

// Simple health check for hosting platforms (e.g. Railway)
app.get('/healthz', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
