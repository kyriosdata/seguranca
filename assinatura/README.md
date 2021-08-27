## Implementação de serviços básicos para assinatura digital

Uma única classe, _Certificado_, é oferecida juntamente com 
métodos que permitem assinar e verificar assinaturas, com 
base nas chaves pública e privada de um certificado digital.

## Como referenciar (Maven)

```xml
<dependencies>
  <dependency>
    <groupId>com.github.kyriosdata</groupId>
    <artifactId>assinatura</artifactId>
    <version>2021.0827.1</version>
  </dependency>
</dependencies>
```

## Como referenciar (Gradle)

```groovy
dependencies {
    implementation 'com.github.kyriosdata:assinatura'
}
```


## Sequências de ações para segurança

- Gerar par de chaves
  - alias: **teste**
  - keystore: **assinar.keystore**
  - senha: **keystore**
  - `keytool -genkey -alias teste -keyalg RSA -keystore assinar.keystore -storetype pkcs12`
- Listar conteúdo de _keystore_  
  - `keytool -list -v -keystore assinar.keystore -storetype PKCS12`
- Exportar chave pública (PEM) (alias: **teste**)
  - `keytool -export -alias teste -keystore assinar.keystore -file publico.pem`
- Exportar chave pública (cert) 
  - `keytool -export -alias teste -keystore assinar.keystore -rfc -file publico.cert`