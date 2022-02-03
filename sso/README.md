## Segurança usando SSO (Single Sign-On)

### Gerando certificado (https)

O comando abaixo irá requisitar uma senha (_passphrase_) 
para acesso ao certificado a ser gerado, use o valor "privatekey".
Este valor é empregado pelo código (server.js). 

- `openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365`
 