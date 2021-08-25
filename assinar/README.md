## Sequências de ações para segurança

- Gerar par de chaves (keystore: **assinar.keystore**) (senha: **keystore**)
  - `keytool -genkey -alias teste -keyalg RSA -keystore assinar.keystore -storetype pkcs12`
- Listar conteúdo de _keystore_  
  - `keytool -list -v -keystore assinar.keystore -storetype PKCS12`
- Exportar chave pública (PEM) (alias: **teste**)
  - `keytool -export -alias teste -keystore assinar.keystore -file publico.pem`
- Exportar chave pública (cert) 
  - `keytool -export -alias teste -keystore assinar.keystore -rfc -file publico.cert`