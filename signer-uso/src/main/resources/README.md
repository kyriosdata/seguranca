# Links relevantes

- Converting a Java Keystore Into PEM Format (https://www.baeldung.com/java-keystore-convert-to-pem-format)

# Keystore gerado com keytool (keystore.jks)

- Senha: keystore

# Keystore obtido a partir do anterior (keystore.p12)

- Senha: keystore


# Keystore no formato PEM (keystore.pem)

- Senha: keystore
- Pass phrase: keystore

Gerado usando openssl:

- `openssl pkcs12 -in keystore.p12 -out keystore.pem`

# Certificado (crt) 

- `openssl pkcs12 -in keystore.p12 -nokeys -out keystore.crt`

# Certificado (cer)

- `keytool -export -alias first-key-pair -storepass keystore -file first-key-pair.cer -keystore keystore.jks`