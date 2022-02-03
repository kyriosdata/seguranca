const https = require("https");
const path = require("path");
const express = require("express");
const fs = require("fs");

const app = express();

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/segredo", (req, res) => {
    return res.send("Segredo");
});

// Configurações
const PORT = process.env.PORT || 3000;
const PASSPHRASE = "privatekey";

const OPTIONS = {
    key: fs.readFileSync("key.pem"),
    cert: fs.readFileSync("cert.pem"),
    passphrase: PASSPHRASE,
};

https.createServer(OPTIONS, app).listen(PORT, () => {
    console.log(`Aguardando na porta ${PORT}`);
});

