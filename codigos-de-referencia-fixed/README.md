##### O que são os Códigos de Referência?

Os Códigos de Referência do Padrão Brasileiro de Assinatura Digital constituem
a implementação de referência dos padrões pertinentes a regulamentação de
assinaturas digitais no âmbito da Infraestrutura de Chaves Públicas Brasileira
(ICP-Brasil). Têm como público-alvo fornecedores de aplicações e plataformas
que desejam oferecer suporte a assinaturas digitais ICP-Brasil. Os Códigos de
Referência visam promover uma maior interoperabilidade entre tais aplicações
e facilitar a implementação dos padrões, simultaneamente oferecendo meios de
aprimorar o próprio conjunto normativo.

##### Qual é sua função?

Criar e verificar assinaturas com certificado ICP-Brasil conforme o documento
[DOC-ICP-15](https://www.gov.br/iti/pt-br/centrais-de-conteudo/doc-icp-15-v-3-0-visao-geral-sobre-assin-dig-na-icp-brasil-pdf),
regulamentado pelo [Instituto Nacional de Tecnologia da
Informação](https://gov.br/iti) (ITI).

##### Como estão organizados?

A principal característica que permeia os Códigos de Referência é o forte uso
de reflexão, um conceito relacionado a metaprogramação, para elaborar uma
orientação a componentes, permitindo a modularização de algumas partes da base
de código. Mais detalhes sobre esta abordagem podem ser lidos [nesta
monografia](https://repositorio.ufsc.br/handle/123456789/184160).

A base de código é programada em Java e segue o padrão
[Maven](https://maven.apache.org), portanto o código-fonte está em
`codigos-de-referencia-core/src/main/java`. Testes unitários, localizados em
`codigos-de-referencia-core/src/test/java`, podem ser executados com `mvn
test`. Comandos `mvn` são usualmente executados na pasta raiz do código-fonte.

A execução do comando `mvn package` gera automaticamente a documentação da base
de código, localizada na pasta `docs`, e dois entregáveis na forma de arquivos
WAR (_web application archive_), ambos na pasta `target`:

* O [Verificador de Conformidade](https://verificador.iti.gov.br), verificador
  oficial de assinaturas digitais da ICP-Brasil, cuja execução é iniciada
  a partir da classe `IndexServlet`. Como este sistema é utilizado em produção,
  sua documentação é detalhada abaixo.
* O [Assinador de Referência](https://pbad.labsec.ufsc.br/signer-hom), cuja
  execução é iniciada a partir da classe `SignerServlet`.

##### Como instalar e executar o Verificador de Conformidade?

Para executar corretamente, o Verificador necessita de no mínimo 256 MB de
memória RAM e um microprocessador de arquitetura x86-64 com dois núcleos
físicos de processamento. Entretanto, o desempenho do Verificador será
diretamente proporcional aos recursos disponíveis na máquina, especialmente ao
verificar múltiplos arquivos simultaneamente. Portanto, é recomendado **8 GB de
memória RAM e oito núcleos físicos de processamento** para um desempenho
aceitável.

O pacote do Verificador ocupa cerca de **35 MB** em disco. Além disso, arquivos
de certificados digitais e listas de certificados revogados (LCRs) são
armazenados localmente para evitar transferências de arquivos repetidas,
e assim avaliar assinaturas digitais mais rapidamente. Neste contexto, a pasta
escolhida é `/tmp/verificador-de-conformidade`, e sugere-se que cerca de **1 GB
de espaço em disco** seja reservado para o uso estendido desta funcionalidade.

Os Códigos de Referência necessitam de **Java 15** (OpenJDK, Eclipse J9 etc.)
rodando sob qualquer distribuição GNU/Linux (Debian, openSUSE etc.) para que
sejam executados corretamente. Como o Verificador é uma aplicação web, um
servidor de aplicação que implemente o padrão **Jakarta Servlet 5.0** (Apache
Tomcat 10.0+, GlassFish 6+) também é necessário.

O [servidor de homologação](https://pbad.labsec.ufsc.br/verifier-hom) do
Verificador utiliza **Ubuntu 20.04 LTS, OpenJDK 15 e [Apache Tomcat
10](https://tomcat.apache.org)**, por exemplo. Entretanto, é possível executar
o Verificador de outras maneiras. O comando abaixo utiliza a plataforma
[Docker](https://docker.com) para executar uma instância local do Verificador
de Conformidade, compilada para o caminho `/path/to/verifier.war`,
disponibilizando-a em http://localhost:8080/verifier-docker.

```
docker run -it -p 8080:8080 tomcat:10.0.5-jdk15-adoptopenjdk-openj9 \
  -v /path/to/verifier.war:/usr/local/tomcat/webapps/verifier-docker.war
```

As dependências do Verificador são obtidas automaticamente no seu processo de
empacotamento, e podem ser listadas explicitamente com o comando `mvn
dependency:tree`, ou verificadas nos arquivos `pom.xml`. O Verificador aceita
arquivos assinados digitalmente como sua entrada, sejam estes com assinaturas
anexadas, destacadas ou embarcadas. Como saída, produz relatórios em PDF ou
HTML contendo várias informações sobre a validade das mesmas.

Para instalar o Verificador, o processo é dependente do servidor de aplicação
escolhido. No caso do Apache Tomcat, basta copiar o arquivo WAR para a pasta de
aplicações web do servidor de aplicação (`$CATALINA_BASE/webapps`, onde
`$CATALINA_BASE` depende do [método de
instalação](https://tomcat.apache.org/tomcat-10.0-doc/introduction.html) do
Apache Tomcat).

Informações sobre o processo de verificação de assinaturas são registradas
através do servidor de aplicação, por exemplo em `$CATALINA_BASE/logs` no caso
do Apache Tomcat. Problemas no funcionamento do Verificador serão expostos
através desses registros, que podem ser enviados para os desenvolvedores dos
Códigos de Referência pois auxiliam em possíveis correções na base de código.

O Verificador necessita realizar download de artefatos utilizados no processo
de verificação de assinaturas digitais através dos protocolos HTTP, HTTPS
e LDAP. Portanto, a comunicação através destes protocolos pelo Verificador não
deve ser proibida pelo sistema operacional ou outras aplicações.

##### O Verificador pode verificar assinaturas de outras ICPs?

O Verificador de Conformidade verifica assinaturas de acordo com um conjunto de
âncoras de confiança, utilizadas na checagem do caminho de certificação do
assinante através da extensão de certificado [_Authority Information
Access_](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1). No
âmbito da ICP-Brasil, estas âncoras são os certificados vigentes da [Autoridade
Certificadora
Raiz](https://www.gov.br/iti/pt-br/assuntos/repositorio/repositorio-ac-raiz)
(AC-Raiz). Este conjunto de âncoras pode ser estendido para que o Verificador
suporte assinaturas de outras ICPs.

Esta configuração é feita no arquivo `web.xml` do Verificador. Este arquivo
está dentro da pasta `WEB-INF` no local onde o servidor de aplicação
descompacta o arquivo WAR para execução. No caso do Apache Tomcat, o caminho
é `$CATALINA_BASE/webapps/verifier-$VERSION/WEB-INF/web.xml`.

No arquivo `web.xml`, estão definidos dois parâmetros relacionados às âncoras
de confiança utilizados durante a execução do Verificador:

* o parâmetro `trustAnchorsDirectory` indica em qual diretório as âncoras serão
  buscadas. O usuário do sistema operacional executando a aplicação do
  Verificador deve ter permissão de leitura e escrita de arquivos neste
  diretório;
* o parâmetro `trustAnchorsURLs` recebe uma lista de URLs separadas por
  vírgulas, através das quais os certificados serão obtidos e salvos no
  diretório especificado acima.

Para adicionar novas âncoras de confiança, basta reuni-las no diretório
especificado por `trustAnchorsDirectory`, ou adicionar as URLs desejadas no
arquivo `web.xml`. Na inicialização do Verificador, será feita a leitura dos
arquivos no diretório definido e também o download dos certificados utilizando
as URLs listadas. Após modificações no arquivo `web.xml`, o servidor de
aplicação precisa ser reiniciado para que as modificações entrem em vigor.

Por padrão, o diretório especificado
é `/tmp/verificador-de-conformidade/Cache/trust-anchors/` e as URLs são das
Autoridades Certificadoras Raiz vigentes da ICP-Brasil. Os dois modos de
obtenção dos certificados podem ser usados em conjunto ou então apenas um
deles, dependendo do que mais se adequar na situação. O diretório especificado
pode não conter nenhum certificado e todos são obtidos através do download
pelas URLs, ou então caso um certificado não esteja disponível através de URL,
o mesmo pode ser adicionado ao diretório manualmente. Mais de uma ICP pode ser
aceita ao mesmo tempo em uma instância do Verificador.

##### O Verificador pode ser utilizado de maneira programática?

O Verificador de Conformidade expõe os _endpoints_ `/inicio`, `/webreport`
e `/report` para submissão de assinaturas através de requisições POST.

* O _endpoint_ `/inicio` retorna uma avaliação inicial em JSON do arquivo
  enviado, identificando se o mesmo é passível de verificação pela aplicação;
* o _endpoint_ `/webreport` é utilizado pela plataforma web do Verificador para
  obter os relatórios de assinaturas em HTML;
* o _endpoint_ `/report` pode ser utilizado para obter relatórios de
  verificação de assinaturas em XML ou JSON de maneira programática.

Detalhes do uso e respostas dos _endpoints_ estão na classe
[`IndexServlet.java`](codigos-de-referencia-core/src/main/java/br/ufsc/labsec/signature/conformanceVerifier/IndexServlet.java)
para `/inicio`
e [`SimpleServlet.java`](codigos-de-referencia-core/src/main/java/br/ufsc/labsec/signature/conformanceVerifier/SimpleServlet.java)
para `/report`.

Há a possibilidade de restrição de acesso do _endpoint_ `/report` através da
configuração do arquivo `web.xml`, como descrito na classe
[`SimpleServlet.java`](codigos-de-referencia-core/src/main/java/br/ufsc/labsec/signature/conformanceVerifier/SimpleServlet.java). Adicionalmente,
é possível fazer uma configuração de limitação de requisições ao _endpoint_
`/webreport`, detalhada em
[`CompleteServlet.java`](codigos-de-referencia-core/src/main/java/br/ufsc/labsec/signature/conformanceVerifier/CompleteServlet.java).
