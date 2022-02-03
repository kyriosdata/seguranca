const https = require("https");
const path = require("path");
const express = require("express");
const fs = require("fs");
const helmet = require("helmet");

const app = express();

// Segurança por headers
app.use(helmet());

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/segredo", (req, res) => {
    return res.send("Segredo");
});

// SEGURANÇA: use vars de ambiente
const PORT = process.env.PORT || 3000;
const PASSPHRASE = process.env.PASSPHRASE || "privatekey";

const OPTIONS = {
    key: fs.readFileSync("key.pem"),
    cert: fs.readFileSync("cert.pem"),
    passphrase: PASSPHRASE,
};

https.createServer(OPTIONS, app).listen(PORT, () => {
    console.log(`Aguardando na porta ${PORT}`);
});

