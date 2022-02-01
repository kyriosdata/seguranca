const path = require("path");
const express = require("express");

const aplicacao = express();

// Porta padrão (3000) se não definida na var de ambiente
const PORT = process.env.PORT || 3000;

aplicacao.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

aplicacao.get("/segredo", (req, res) => {
    return res.send("Segredo");
});

aplicacao.listen(PORT, () => {
    console.log(`Aguardando na porta ${PORT}`);
});

