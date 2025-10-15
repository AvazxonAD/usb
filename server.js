require("./index");
require("colors");
const express = require("express");
const app = express();

app.listen(8082, () => console.log("Node.js running on port 8082".bgBlue));
