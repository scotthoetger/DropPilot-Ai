
const express = require("express");
const app = express();

const PORT = process.env.PORT || 3000;

app.get("/", (req, res) => {
  res.send("DropPilot AI is running!");
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`DropPilot AI running on port ${PORT}`);
});
  