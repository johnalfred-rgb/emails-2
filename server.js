const express = require('express');
const path = require('path');

const app = express();

// Serve all files in the workspace root (including email_blast.html)
app.use(express.static(path.join(__dirname)));

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
