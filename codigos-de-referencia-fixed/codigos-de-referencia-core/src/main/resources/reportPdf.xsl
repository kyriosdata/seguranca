<?xml version="1.0" encoding="UTF-8"?>

<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:fo="http://www.w3.org/1999/XSL/Format">


    <xsl:template match="/">

        <fo:root>

            <fo:layout-master-set>
                <fo:simple-page-master master-name="my-page">
                    <fo:region-body margin="0.7in" />
                    <!-- TODO definições da pagina vem aqui -->

                </fo:simple-page-master>
            </fo:layout-master-set>

            <fo:page-sequence master-reference="my-page">
                <fo:flow flow-name="xsl-region-body" font-size="11pt">
                    <xsl:param name="signatureValidityAttr"/>
                    <fo:block font-size="11pt" text-align="center"
                              line-height="5.5" font-weight="bold">
                        <fo:inline text-transform="uppercase">Relatório&#x0020;</fo:inline>
                            <xsl:value-of select="report/number" />
                        - <fo:inline text-transform="uppercase"><xsl:value-of select="$signatureValidityAttr"/></fo:inline>
                    </fo:block>

                    <!-- Informações basicas -->

                    <fo:table table-layout="fixed" width="100%" border="none"
                              text-align="center">

                        <fo:table-column column-width="2in" />
                        <fo:table-column column-width="4in" />

                        <fo:table-body>
                            <fo:table-row>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start"> Versão do
                                        software
                                    </fo:block>
                                </fo:table-cell>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start" color="gray">
                                        :
                                        <xsl:value-of select="report/software/version" />
                                    </fo:block>
                                </fo:table-cell>
                            </fo:table-row>
                            <fo:table-row>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start"> Nome </fo:block>
                                </fo:table-cell>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start" color="gray">
                                        :
                                        <xsl:value-of select="report/software/name" />
                                    </fo:block>
                                </fo:table-cell>
                            </fo:table-row>
                            <fo:table-row>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start"> Arquivo Fonte </fo:block>
                                </fo:table-cell>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start" color="gray">
                                        :
                                        <xsl:value-of select="report/software/sourceFile" />
                                    </fo:block>
                                </fo:table-cell>
                            </fo:table-row>
                            <fo:table-row>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start"> Data de
                                        verificação
                                    </fo:block>
                                </fo:table-cell>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start" color="gray">
                                        :
                                        <xsl:value-of select="report/date/verificationDate" />
                                    </fo:block>
                                </fo:table-cell>
                            </fo:table-row>
                            <fo:table-row>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start"> Fonte da data
                                    </fo:block>
                                </fo:table-cell>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start" color="gray">
                                        :
                                        <xsl:value-of select="report/date/sourceOfDate" />
                                    </fo:block>
                                </fo:table-cell>
                            </fo:table-row>
                        </fo:table-body>
                    </fo:table>

                    <!-- Informações da LPA -->

                    <xsl:if test="report/lpa/period != ''">
                        <fo:block font-size="11pt" text-align="left" line-height="3.5"
                                  font-weight="bold">
                            <fo:inline text-transform="uppercase">LPA</fo:inline>
                        </fo:block>

                        <fo:table table-layout="fixed" width="100%" border="none"
                                  text-align="center">

                            <fo:table-column column-width="2in" />
                            <fo:table-column column-width="4.8in" />

                            <fo:table-body>
                                <fo:table-row>
                                    <fo:table-cell padding="2pt" border="none">
                                        <fo:block font-size="11pt" text-align="start"> Online
                                        </fo:block>
                                    </fo:table-cell>
                                    <fo:table-cell padding="2pt" border="none">
                                        <fo:block font-size="11pt" text-align="start" color="gray">
                                            :
                                            <xsl:choose>
                                                <xsl:when test="report/lpa/online='True'">
                                                    Sim
                                                </xsl:when>
                                                <xsl:otherwise>
                                                    Não
                                                </xsl:otherwise>
                                            </xsl:choose>
                                        </fo:block>
                                    </fo:table-cell>
                                </fo:table-row>
                                <fo:table-row>
                                    <fo:table-cell padding="2pt" border="none">
                                        <fo:block font-size="11pt" text-align="start"> Status da LPA
                                        </fo:block>
                                    </fo:table-cell>
                                    <fo:table-cell padding="2pt" border="none">
                                        <fo:block font-size="11pt" text-align="start" color="gray">
                                            :
                                            <xsl:choose>
                                                <xsl:when test="report/lpa/valid='True'">
                                                    Aprovada
                                                </xsl:when>
                                                <xsl:otherwise>
                                                    Reprovada
                                                </xsl:otherwise>
                                            </xsl:choose>
                                        </fo:block>
                                    </fo:table-cell>
                                </fo:table-row>
                                <fo:table-row>
                                    <fo:table-cell padding="2pt" border="none">
                                        <fo:block font-size="11pt" text-align="start"> Próxima emissão
                                        </fo:block>
                                    </fo:table-cell>
                                    <fo:table-cell padding="2pt" border="none">
                                        <fo:block font-size="11pt" text-align="start" color="gray">
                                            :
                                            <xsl:value-of select="report/lpa/period" />
                                        </fo:block>
                                    </fo:table-cell>
                                </fo:table-row>
                                <fo:table-row>
                                    <fo:table-cell padding="2pt" border="none">
                                        <fo:block font-size="11pt" text-align="start"> Expirada
                                        </fo:block>
                                    </fo:table-cell>
                                    <fo:table-cell padding="2pt" border="none">
                                        <fo:block font-size="11pt" text-align="start" color="gray">
                                            :
                                            <xsl:choose>
                                                <xsl:when test="report/lpa/expired='True'">
                                                    Sim
                                                </xsl:when>
                                                <xsl:otherwise>
                                                    Não
                                                </xsl:otherwise>
                                            </xsl:choose>
                                        </fo:block>
                                    </fo:table-cell>
                                </fo:table-row>
                                <fo:table-row>
                                    <fo:table-cell padding="2pt" border="none">
                                        <fo:block font-size="11pt" text-align="start"> Versão
                                        </fo:block>
                                    </fo:table-cell>
                                    <fo:table-cell padding="2pt" border="none">
                                        <fo:block font-size="11pt" text-align="start" color="gray">
                                            :
                                            <xsl:value-of select="report/lpa/version" />
                                        </fo:block>
                                    </fo:table-cell>
                                </fo:table-row>
                            </fo:table-body>
                        </fo:table>
                    </xsl:if>

                    <xsl:if test="report/pas/pa">
                        <fo:block font-size="11pt" text-align="left" line-height="3"
                                  font-weight="bold" space-before="5mm">
                            <fo:inline text-transform="uppercase">PA</fo:inline>
                        </fo:block>

                        <!-- Informações das PAs -->
                        <xsl:apply-templates select="report/pas/pa" />
                    </xsl:if>

                </fo:flow>
            </fo:page-sequence>

            <fo:page-sequence master-reference="my-page">
                <fo:flow flow-name="xsl-region-body" font-size="11pt">
                    <!-- Informações das Assinaturas -->
                    <fo:block font-size="11pt" text-align="left" line-height="3"
                              font-weight="bold" space-before="5mm">
                        <fo:inline text-transform="uppercase">Assinaturas</fo:inline>
                    </fo:block>

                    <xsl:apply-templates select="report/signatures/signature" />
                    <xsl:apply-templates select="report/signatures/notIcpbrSignature" />
                </fo:flow>
            </fo:page-sequence>

        </fo:root>


    </xsl:template>


    <xsl:template match="pa">
        <fo:table table-layout="fixed" width="100%" border="none"
                  text-align="center" space-after="5mm" page-break-inside="avoid">

            <fo:table-column column-width="2in" />
            <fo:table-column column-width="4.8in" />

            <fo:table-body>
                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" text-align="start"> OID </fo:block>
                    </fo:table-cell>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" text-align="start" color="gray">
                            :
                            <xsl:value-of select="oid" />
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>
                <xsl:if test="contains(oid, 'PA_')">
                    <fo:table-row>
                        <fo:table-cell padding="2pt" border="none">
                            <fo:block font-size="11pt" text-align="start"> Utilizada a PA
                                online?
                            </fo:block>
                        </fo:table-cell>
                        <fo:table-cell padding="2pt" border="none">
                            <fo:block font-size="11pt" text-align="start" color="gray">
                                :
                                <xsl:choose>
                                    <xsl:when test="online='True'">
                                        Sim
                                    </xsl:when>
                                    <xsl:otherwise>
                                        Não
                                    </xsl:otherwise>
                                </xsl:choose>
                            </fo:block>
                        </fo:table-cell>
                    </fo:table-row>
                    <fo:table-row>
                        <fo:table-cell padding="2pt" border="none">
                            <fo:block font-size="11pt" text-align="start"> Íntegra segundo a
                                LPA
                            </fo:block>
                        </fo:table-cell>
                        <fo:table-cell padding="2pt" border="none">
                            <fo:block font-size="11pt" text-align="start" color="gray">
                                :
                                <xsl:choose>
                                    <xsl:when test="validLpa='True'">
                                        Sim
                                    </xsl:when>
                                    <xsl:otherwise>
                                        Não
                                    </xsl:otherwise>
                                </xsl:choose>
                            </fo:block>
                        </fo:table-cell>
                    </fo:table-row>
                    <fo:table-row>
                        <fo:table-cell padding="2pt" border="none">
                            <fo:block font-size="11pt" text-align="start"> Íntegra </fo:block>
                        </fo:table-cell>
                        <fo:table-cell padding="2pt" border="none">
                            <fo:block font-size="11pt" text-align="start" color="gray">
                                :
                                <xsl:choose>
                                    <xsl:when test="valid='True'">
                                        Sim
                                    </xsl:when>
                                    <xsl:otherwise>
                                        Não
                                    </xsl:otherwise>
                                </xsl:choose>
                            </fo:block>
                        </fo:table-cell>
                    </fo:table-row>
                    <xsl:choose>
                        <xsl:when test="not(period='')">
                            <fo:table-row>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start"> Aprovada no período </fo:block>
                                </fo:table-cell>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start" color="gray">
                                        :
                                        <xsl:value-of select="period" />
                                    </fo:block>
                                </fo:table-cell>
                            </fo:table-row>
                        </xsl:when>
                    </xsl:choose>
                    <xsl:choose>
                        <xsl:when test="not(period='')">
                            <fo:table-row>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start"> Status </fo:block>
                                </fo:table-cell>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start" color="gray">
                                        :
                                        <xsl:choose>
                                            <xsl:when test="revoked='True'">
                                                Revogada
                                            </xsl:when>
                                            <xsl:when test="expired='True'">
                                                Expirada
                                            </xsl:when>
                                            <xsl:otherwise>
                                                Aprovada
                                            </xsl:otherwise>
                                        </xsl:choose>
                                    </fo:block>
                                </fo:table-cell>
                            </fo:table-row>
                        </xsl:when>
                    </xsl:choose>
                </xsl:if>
                <xsl:if test="not(error = '')">
                    <fo:table-row>
                        <fo:table-cell padding="2pt" border="none">
                            <fo:block font-size="11pt" text-align="start"> Mensagem de erro </fo:block>
                        </fo:table-cell>
                        <fo:table-cell padding="2pt" border="none">
                            <fo:block font-size="11pt" text-align="start" color="gray">
                                :
                                <xsl:value-of select="error"/>
                            </fo:block>
                        </fo:table-cell>
                    </fo:table-row>
                </xsl:if>
            </fo:table-body>
        </fo:table>

    </xsl:template>

    <xsl:template match="signature">

        <!-- ASSINANTE -->

        <fo:table table-layout="fixed" width="100%" border="none"
                  text-align="center" space-after="0mm" page-break-inside="avoid">

            <fo:table-column column-width="1.9in" />
            <fo:table-column column-width="4.8in" />

            <fo:table-body>

                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" font-weight="bold" text-align="start">
                            Assinante
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>


                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" text-align="start">
                            Assinante
                        </fo:block>
                    </fo:table-cell>
                    <fo:table-cell>
                        <fo:block font-size="11pt" text-align="start" color="gray">
                            :
                            <xsl:value-of select="certification/signer/subjectName" />
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>

                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" text-align="start">
                            Status da assinatura
                        </fo:block>
                    </fo:table-cell>
                    <fo:table-cell>
                        <fo:block font-size="11pt" text-align="start" color="gray">
                            :
                            <xsl:value-of select="certification/signer/validSignature" />
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>

                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" text-align="start">
                            Caminho de
                            certificação
                        </fo:block>
                    </fo:table-cell>
                    <fo:table-cell>
                        <fo:block font-size="11pt" text-align="start" color="gray">
                            :
                            <xsl:choose>
                                <xsl:when test="certification/signer/certPathValid='Valid'">
                                    Aprovado
                                </xsl:when>
                                <xsl:when test="certification/signer/certPathValid='Revoked'">
                                    Revogado
                                </xsl:when>
                                <xsl:when test="certification/signer/certPathValid='Expired'">
                                    Expirado
                                </xsl:when>
                                <xsl:when test="certification/signer/certPathValid='NotValidYet'">
                                    Ainda não validado
                                </xsl:when>
                                <xsl:when test="certification/signer/certPathValid='Unknown'">
                                    Desconhecido
                                </xsl:when>
                                <xsl:otherwise>
                                    Reprovado.
                                </xsl:otherwise>
                            </xsl:choose>
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>

                <xsl:choose>
                    <xsl:when test="certification/signer/certPathMessage != ''">
                        <fo:table-row>
                            <fo:table-cell padding="2pt" border="none">
                                <fo:block font-size="11pt" text-align="start">
                                    Mensagem de erro
                                </fo:block>
                            </fo:table-cell>
                            <fo:table-cell>
                                <fo:block font-size="11pt" text-align="start" color="gray">
                                    :
                                    <xsl:value-of select="certification/signer/certPathMessage" />
                                </fo:block>
                            </fo:table-cell>
                        </fo:table-row>
                    </xsl:when>
                </xsl:choose>

                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" text-align="start">
                            Estrutura
                        </fo:block>
                    </fo:table-cell>
                    <fo:table-cell>
                        <fo:block font-size="11pt" text-align="start" color="gray">
                            :
                            <xsl:choose>
                                <xsl:when test="integrity/schema='True'">
                                    De acordo.
                                </xsl:when>
                                <xsl:when test="integrity/schema='Unknown'">
                                    Impossível determinar.
                                </xsl:when>
                                <xsl:otherwise>
                                    Não está de acordo.
                                </xsl:otherwise>
                            </xsl:choose>
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>

                <xsl:choose>
                    <xsl:when test="integrity/schema!='True'">
                        <fo:table-row>
                            <fo:table-cell padding="2pt" border="none">
                                <fo:block font-size="11pt" text-align="start">
                                    Mensagem de erro
                                </fo:block>
                            </fo:table-cell>
                            <fo:table-cell>
                                <fo:block font-size="11pt" text-align="start" color="gray">
                                    :
                                    <xsl:value-of select="integrity/schemaMessage" />
                                </fo:block>
                            </fo:table-cell>
                        </fo:table-row>
                    </xsl:when>
                </xsl:choose>

                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" text-align="start">
                            Cifra assimétrica
                        </fo:block>
                    </fo:table-cell>
                    <fo:table-cell>
                        <fo:block font-size="11pt" text-align="start" color="gray">
                            :
                            <xsl:choose>
                                <xsl:when test="integrity/asymmetricCipher='True'">
                                    Aprovada.
                                </xsl:when>
                                <xsl:otherwise>
                                    Reprovada.
                                </xsl:otherwise>
                            </xsl:choose>
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>

                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" text-align="start">
                            Resumo
                            criptográfico
                        </fo:block>
                    </fo:table-cell>
                    <fo:table-cell>
                        <fo:block font-size="11pt" text-align="start" color="gray">
                            :
                            <xsl:choose>
                                <xsl:when test="integrity/hash='True'">
                                    Correto.
                                </xsl:when>
                                <xsl:otherwise>
                                    Incorreto.
                                </xsl:otherwise>
                            </xsl:choose>
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>

                <xsl:if test="(attributes/requiredAttributes/requiredAttribute)">
                    <fo:table-row>
                        <fo:table-cell padding="2pt" border="none">
                            <fo:block font-size="11pt" text-align="start">
                                Atributos obrigatórios
                            </fo:block>
                        </fo:table-cell>
                        <fo:table-cell>
                            <fo:block font-size="11pt" text-align="start" color="gray">
                                :
                                <xsl:choose>
                                    <xsl:when test="attributeValid='True'">
                                        Aprovados.
                                    </xsl:when>
                                    <xsl:otherwise>
                                        Existe ao menos um atributo obrigatório reprovado.
                                    </xsl:otherwise>
                                </xsl:choose>
                            </fo:block>
                        </fo:table-cell>
                    </fo:table-row>
                </xsl:if>

                <xsl:if test="paRules/mandatedCertificateInfo != ''">
                    <fo:table-row>
                        <fo:table-cell padding="2pt" border="none">
                            <fo:block font-size="11pt" text-align="start"> Certificados
                                necessários
                            </fo:block>
                        </fo:table-cell>
                        <fo:table-cell>
                            <fo:block font-size="11pt" text-align="start" color="gray">
                                :
                                <xsl:value-of select="paRules/mandatedCertificateInfo" />
                            </fo:block>
                        </fo:table-cell>
                    </fo:table-row>
                </xsl:if>

                <xsl:if test="alertMessage != ''">
                    <fo:table-row>
                        <fo:table-cell padding="2pt" border="none">
                            <fo:block font-size="11pt" text-align="start">
                                Alerta
                            </fo:block>
                        </fo:table-cell>
                        <fo:table-cell>
                            <fo:block font-size="11pt" text-align="start" color="gray">
                                :
                                <xsl:value-of select="alertMessage" />
                            </fo:block>
                        </fo:table-cell>
                    </fo:table-row>
                </xsl:if>

            </fo:table-body>

        </fo:table>


        <!-- Certificiados utilizados -->
        <fo:block font-size="11pt" text-align="left" line-height="2.5"
                  font-weight="bold">
            <fo:inline>Certificados utilizados</fo:inline>
        </fo:block>

        <xsl:apply-templates select="certification/signer/certificate" />


        <!-- Atributos Obrigatórios -->
        <xsl:if test="(attributes/requiredAttributes/requiredAttribute)">
            <fo:block font-size="11pt" text-align="left" line-height="2.5"
                      font-weight="bold">
                <fo:inline>Atributos Obrigatórios</fo:inline>
            </fo:block>

            <fo:block font-size="11pt" text-align="start" text-indent="1mm">
                <xsl:for-each select="attributes/requiredAttributes/requiredAttribute">

                    <fo:table table-layout="fixed" width="100%" border="none"
                              text-align="center" space-after="2mm" page-break-inside="avoid">

                        <fo:table-column column-width="1.9in" />
                        <fo:table-column column-width="4in" />

                        <fo:table-body>

                            <fo:table-row>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start">
                                        Nome do atributo
                                    </fo:block>
                                </fo:table-cell>
                                <fo:table-cell>
                                    <fo:block font-size="11pt" text-align="start" color="gray">
                                        :
                                        <xsl:value-of select="name" />
                                    </fo:block>
                                </fo:table-cell>
                            </fo:table-row>

                            <fo:table-row>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start">
                                        Corretude
                                    </fo:block>
                                </fo:table-cell>
                                <fo:table-cell>
                                    <fo:block font-size="11pt" text-align="start" color="gray">
                                        :
                                        <xsl:choose>
                                            <xsl:when test="error='False'">
                                                Aprovado
                                            </xsl:when>
                                            <xsl:when test="error='Not validated'">
                                                Não verificado
                                                <xsl:if test="not(errorMessage='')">
                                                    . <xsl:value-of
                                                            select="errorMessage"/>
                                                </xsl:if>
                                            </xsl:when>
                                            <xsl:otherwise>
                                                Reprovado
                                            </xsl:otherwise>
                                        </xsl:choose>
                                    </fo:block>
                                </fo:table-cell>
                            </fo:table-row>

                            <xsl:choose>
                                <xsl:when test="error='True'">
                                    <fo:table-row>
                                        <fo:table-cell padding="2pt" border="none">
                                            <fo:block font-size="11pt" text-align="start">
                                                Mensagem de
                                                erro
                                            </fo:block>
                                        </fo:table-cell>
                                        <fo:table-cell>
                                            <fo:block font-size="11pt" text-align="start" color="gray">
                                                :
                                                <xsl:value-of select="errorMessage" />
                                            </fo:block>
                                        </fo:table-cell>
                                    </fo:table-row>
                                </xsl:when>
                            </xsl:choose>

                            <xsl:if test="alertMessage">
                                <fo:table-row>
                                    <fo:table-cell padding="2pt" border="none">
                                        <fo:block font-size="11pt" text-align="start">
                                            Alerta
                                        </fo:block>
                                    </fo:table-cell>
                                    <fo:table-cell>
                                        <fo:block font-size="11pt" text-align="start" color="gray">
                                            :
                                            <xsl:value-of select="alertMessage" />
                                        </fo:block>
                                    </fo:table-cell>
                                </fo:table-row>
                            </xsl:if>

                        </fo:table-body>
                    </fo:table>

                </xsl:for-each>

            </fo:block>
        </xsl:if>

        <!-- Atributos Opcionais -->
        <xsl:if test="(attributes/optionalAttributes/optionalAttribute)">
            <fo:block font-size="11pt" text-align="left" line-height="2.5"
                      font-weight="bold">
                <fo:inline>Atributos Opcionais</fo:inline>
            </fo:block>

            <fo:block font-size="11pt" text-align="start" text-indent="1mm">
                <xsl:for-each select="attributes/optionalAttributes/optionalAttribute">
                    <fo:table table-layout="fixed" width="100%" border="none"
                              text-align="center" space-after="2mm" page-break-inside="avoid">

                        <fo:table-column column-width="1.9in" />
                        <fo:table-column column-width="4in" />

                        <fo:table-body>

                            <fo:table-row>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start">
                                        Nome do atributo
                                    </fo:block>
                                </fo:table-cell>
                                <fo:table-cell>
                                    <fo:block font-size="11pt" text-align="start" color="gray">
                                        :
                                        <xsl:value-of select="name" />
                                    </fo:block>
                                </fo:table-cell>
                            </fo:table-row>

                            <fo:table-row>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start">
                                        Resultado da verificação
                                    </fo:block>
                                </fo:table-cell>
                                <fo:table-cell>
                                    <fo:block font-size="11pt" text-align="start" color="gray">
                                        :
                                        <xsl:choose>
                                            <xsl:when test="error='False'">
                                                Aprovado
                                            </xsl:when>
                                            <xsl:when test="error='Not validated'">
                                                Não verificado
                                                <xsl:if test="not(errorMessage='')">
                                                    . <xsl:value-of
                                                            select="errorMessage"/>
                                                </xsl:if>
                                            </xsl:when>
                                            <xsl:otherwise>
                                                Reprovado
                                            </xsl:otherwise>
                                        </xsl:choose>
                                    </fo:block>
                                </fo:table-cell>
                            </fo:table-row>

                            <xsl:choose>
                                <xsl:when test="error='True'">
                                    <fo:table-row>
                                        <fo:table-cell padding="2pt" border="none">
                                            <fo:block font-size="11pt" text-align="start">
                                                Mensagem de
                                                erro
                                            </fo:block>
                                        </fo:table-cell>
                                        <fo:table-cell>
                                            <fo:block font-size="11pt" text-align="start" color="gray">
                                                :
                                                <xsl:value-of select="errorMessage" />
                                            </fo:block>
                                        </fo:table-cell>
                                    </fo:table-row>
                                </xsl:when>
                            </xsl:choose>

                            <xsl:if test="alertMessage">
                                <fo:table-row>
                                    <fo:table-cell padding="2pt" border="none">
                                        <fo:block font-size="11pt" text-align="start">
                                            Alerta
                                        </fo:block>
                                    </fo:table-cell>
                                    <fo:table-cell>
                                        <fo:block font-size="11pt" text-align="start" color="gray">
                                            :
                                            <xsl:value-of select="alertMessage" />
                                        </fo:block>
                                    </fo:table-cell>
                                </fo:table-row>
                            </xsl:if>

                        </fo:table-body>
                    </fo:table>
                </xsl:for-each>
            </fo:block>
        </xsl:if>

        <!-- Contra-assinaturas -->
        <xsl:if test="counterSignatures">
            <fo:block font-size="11pt" text-align="left" line-height="2.5"
                      font-weight="bold">
                <fo:inline>Contra-assinaturas</fo:inline>
            </fo:block>
            <xsl:apply-templates select="counterSignatures/signature"/>
        </xsl:if>

        <!-- Carimbo do tempo -->
        <xsl:if test="(certification/timeStamps/timeStamp)">
            <fo:block font-size="11pt" text-align="left" line-height="2.5"
                      font-weight="bold">
                <fo:inline>Carimbos do tempo</fo:inline>
            </fo:block>

            <fo:block font-size="11pt" text-align="start" text-indent="5mm">
                <xsl:for-each select="certification/timeStamps/timeStamp">

                    <fo:block font-size="11pt" text-align="left" line-height="2.5"
                              font-weight="bold">
                        <fo:inline>Carimbo do tempo</fo:inline>
                    </fo:block>

                    <!-- ASSINANTE -->

                    <fo:table table-layout="fixed" width="100%" border="none"
                              text-align="center" space-after="1mm" page-break-inside="avoid">

                        <fo:table-column column-width="1.9in" />
                        <fo:table-column column-width="4.8in" />

                        <fo:table-body>

                            <fo:table-row>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start">
                                        Identificador
                                    </fo:block>
                                </fo:table-cell>
                                <fo:table-cell>
                                    <fo:block font-size="11pt" text-align="start" color="gray">
                                        :
                                        <xsl:value-of select="timeStampIdentifier" />
                                    </fo:block>
                                </fo:table-cell>
                            </fo:table-row>

                            <fo:table-row>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start">
                                        Assinante
                                    </fo:block>
                                </fo:table-cell>
                                <fo:table-cell>
                                    <fo:block font-size="11pt" text-align="start" color="gray">
                                        :
                                        <xsl:value-of select="timeStampName" />
                                    </fo:block>
                                </fo:table-cell>
                            </fo:table-row>

                            <fo:table-row>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start">
                                        Data do carimbo
                                    </fo:block>
                                </fo:table-cell>
                                <fo:table-cell>
                                    <fo:block font-size="11pt" text-align="start" color="gray">
                                        :
                                        <xsl:value-of select="timeStampTimeReference" />
                                    </fo:block>
                                </fo:table-cell>
                            </fo:table-row>

                            <fo:table-row>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start">
                                        Caminho de
                                        certificação
                                    </fo:block>
                                </fo:table-cell>
                                <fo:table-cell>
                                    <fo:block font-size="11pt" text-align="start" color="gray">
                                        :
                                        <xsl:choose>
                                            <xsl:when test="certPathValid='Valid'">
                                                Aprovado
                                            </xsl:when>
                                            <xsl:when test="certPathValid='Revoked'">
                                                Revogado
                                            </xsl:when>
                                            <xsl:when test="certPathValid='Expired'">
                                                Expirado
                                            </xsl:when>
                                            <xsl:when test="certPathValid='NotValidYet'">
                                                Ainda não validado
                                            </xsl:when>
                                            <xsl:when test="certPathValid='Unknown'">
                                                Desconhecido
                                            </xsl:when>
                                            <xsl:otherwise>
                                                Reprovado
                                            </xsl:otherwise>
                                        </xsl:choose>
                                    </fo:block>
                                </fo:table-cell>
                            </fo:table-row>

                            <xsl:choose>
                                <xsl:when test="certPathMessage != ''">
                                    <fo:table-row>
                                        <fo:table-cell padding="2pt" border="none">
                                            <fo:block font-size="11pt" text-align="start">
                                                Mensagem de erro
                                            </fo:block>
                                        </fo:table-cell>
                                        <fo:table-cell>
                                            <fo:block font-size="11pt" text-align="start" color="gray">
                                                :
                                                <xsl:value-of select="certPathMessage" />
                                            </fo:block>
                                        </fo:table-cell>
                                    </fo:table-row>
                                </xsl:when>
                            </xsl:choose>

                            <fo:table-row>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start">
                                        Estrutura
                                    </fo:block>
                                </fo:table-cell>
                                <fo:table-cell>
                                    <fo:block font-size="11pt" text-align="start" color="gray">
                                        :
                                        <xsl:choose>
                                            <xsl:when test="integrity/schema='True'">
                                                De acordo.
                                            </xsl:when>
                                            <xsl:when test="integrity/schema='Unknown'">
                                                Impossível determinar.
                                            </xsl:when>
                                            <xsl:otherwise>
                                                Não está de acordo.
                                            </xsl:otherwise>
                                        </xsl:choose>
                                    </fo:block>
                                </fo:table-cell>
                            </fo:table-row>

                            <fo:table-row>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start">
                                        Assinatura
                                    </fo:block>
                                </fo:table-cell>
                                <fo:table-cell>
                                    <fo:block font-size="11pt" text-align="start" color="gray">
                                        :
                                        <xsl:choose>
                                            <xsl:when test="integrity/asymmetricCipher='True'">
                                                Aprovada.
                                            </xsl:when>
                                            <xsl:otherwise>
                                                Reprovada.
                                            </xsl:otherwise>
                                        </xsl:choose>
                                    </fo:block>
                                </fo:table-cell>
                            </fo:table-row>

                            <fo:table-row>
                                <fo:table-cell padding="2pt" border="none">
                                    <fo:block font-size="11pt" text-align="start">
                                        Resumo
                                        criptográfico
                                    </fo:block>
                                </fo:table-cell>
                                <fo:table-cell>
                                    <fo:block font-size="11pt" text-align="start" color="gray">
                                        :
                                        <xsl:choose>
                                            <xsl:when test="integrity/hash='True'">
                                                Correto.
                                            </xsl:when>
                                            <xsl:otherwise>
                                                Incorreto.
                                            </xsl:otherwise>
                                        </xsl:choose>
                                    </fo:block>
                                </fo:table-cell>
                            </fo:table-row>

                        </fo:table-body>

                    </fo:table>


                    <!-- Certificiados utilizados -->
                    <xsl:if test="(certificate)">
                        <fo:block font-size="11pt" text-align="left" line-height="1.5"
                                  font-weight="bold">
                            <fo:inline>Certificados utilizados</fo:inline>
                        </fo:block>

                        <xsl:apply-templates select="certificate" />
                    </xsl:if>

                    <!-- Atributos Obrigatórios -->
                    <xsl:if test="(attributes/requiredAttributes/requiredAttribute)">
                        <fo:block font-size="11pt" text-align="left" line-height="2.5"
                                  font-weight="bold">
                            <fo:inline>Atributos Obrigatórios</fo:inline>
                        </fo:block>

                        <fo:block font-size="11pt" text-align="start" text-indent="5mm">

                            <xsl:for-each select="attributes/requiredAttributes/requiredAttribute">

                                <fo:table table-layout="fixed" width="100%" border="none"
                                          text-align="center" space-after="2mm" page-break-inside="avoid">

                                    <fo:table-column column-width="1.9in" />
                                    <fo:table-column column-width="4.5in" />

                                    <fo:table-body>

                                        <fo:table-row>
                                            <fo:table-cell padding="2pt" border="none">
                                                <fo:block font-size="11pt" text-align="start">
                                                    Nome do
                                                    atributo
                                                </fo:block>
                                            </fo:table-cell>
                                            <fo:table-cell>
                                                <fo:block font-size="11pt" text-align="start" color="gray">
                                                    :
                                                    <xsl:value-of select="name" />
                                                </fo:block>
                                            </fo:table-cell>
                                        </fo:table-row>

                                        <fo:table-row>
                                            <fo:table-cell padding="2pt" border="none">
                                                <fo:block font-size="11pt" text-align="start">
                                                    Corretude
                                                </fo:block>
                                            </fo:table-cell>
                                            <fo:table-cell>
                                                <fo:block font-size="11pt" text-align="start" color="gray">
                                                    :
                                                    <xsl:choose>
                                                        <xsl:when test="error='False'">
                                                            Aprovado
                                                        </xsl:when>
                                                        <xsl:when test="error='Not validated'">
                                                            Não verificado
                                                            <xsl:if test="not(errorMessage='')">
                                                                . <xsl:value-of
                                                                        select="errorMessage"/>
                                                            </xsl:if>
                                                        </xsl:when>
                                                        <xsl:otherwise>
                                                            Reprovado
                                                        </xsl:otherwise>
                                                    </xsl:choose>
                                                </fo:block>
                                            </fo:table-cell>
                                        </fo:table-row>

                                        <xsl:choose>
                                            <xsl:when test="error='True'">
                                                <fo:table-row>
                                                    <fo:table-cell padding="2pt" border="none">
                                                        <fo:block font-size="11pt" text-align="start">
                                                            Mensagem de
                                                            erro
                                                        </fo:block>
                                                    </fo:table-cell>
                                                    <fo:table-cell>
                                                        <fo:block font-size="11pt" text-align="start"
                                                                  color="gray">
                                                            :
                                                            <xsl:value-of select="errorMessage" />
                                                        </fo:block>
                                                    </fo:table-cell>
                                                </fo:table-row>
                                            </xsl:when>
                                        </xsl:choose>

                                        <xsl:if test="alertMessage">
                                            <fo:table-row>
                                                <fo:table-cell padding="2pt" border="none">
                                                    <fo:block font-size="11pt" text-align="start">
                                                        Alerta
                                                    </fo:block>
                                                </fo:table-cell>
                                                <fo:table-cell>
                                                    <fo:block font-size="11pt" text-align="start" color="gray">
                                                        :
                                                        <xsl:value-of select="alertMessage" />
                                                    </fo:block>
                                                </fo:table-cell>
                                            </fo:table-row>
                                        </xsl:if>

                                    </fo:table-body>
                                </fo:table>

                            </xsl:for-each>
                        </fo:block>
                    </xsl:if>

                    <!-- Atributos Opcionais -->
                    <xsl:if test="(attributes/optionalAttributes/optionalAttribute)">
                        <fo:block font-size="11pt" text-align="left" line-height="2.5"
                                  font-weight="bold">
                            <fo:inline>Atributos Opcionais</fo:inline>
                        </fo:block>

                        <fo:block font-size="11pt" text-align="start" text-indent="1mm">
                            <xsl:for-each select="attributes/optionalAttributes/optionalAttribute">
                                <fo:table table-layout="fixed" width="100%" border="none"
                                          text-align="center" space-after="2mm" page-break-inside="avoid">

                                    <fo:table-column column-width="1.9in" />
                                    <fo:table-column column-width="4in" />

                                    <fo:table-body>

                                        <fo:table-row>
                                            <fo:table-cell padding="2pt" border="none">
                                                <fo:block font-size="11pt" text-align="start">
                                                    Nome do
                                                    atributo
                                                </fo:block>
                                            </fo:table-cell>
                                            <fo:table-cell>
                                                <fo:block font-size="11pt" text-align="start" color="gray">
                                                    :
                                                    <xsl:value-of select="name" />
                                                </fo:block>
                                            </fo:table-cell>
                                        </fo:table-row>

                                        <fo:table-row>
                                            <fo:table-cell padding="2pt" border="none">
                                                <fo:block font-size="11pt" text-align="start">
                                                    Resultado da verificação
                                                </fo:block>
                                            </fo:table-cell>
                                            <fo:table-cell>
                                                <fo:block font-size="11pt" text-align="start" color="gray">
                                                    :
                                                    <xsl:choose>
                                                        <xsl:when test="error='False'">
                                                            Aprovado
                                                        </xsl:when>
                                                        <xsl:when test="error='Not validated'">
                                                            Não verificado
                                                            <xsl:if test="not(errorMessage='')">
                                                                . <xsl:value-of
                                                                        select="errorMessage"/>
                                                            </xsl:if>
                                                        </xsl:when>
                                                        <xsl:otherwise>
                                                            Reprovado
                                                        </xsl:otherwise>
                                                    </xsl:choose>
                                                </fo:block>
                                            </fo:table-cell>
                                        </fo:table-row>

                                        <xsl:choose>
                                            <xsl:when test="error='True'">
                                                <fo:table-row>
                                                    <fo:table-cell padding="2pt" border="none">
                                                        <fo:block font-size="11pt" text-align="start">
                                                            Mensagem de
                                                            erro
                                                        </fo:block>
                                                    </fo:table-cell>
                                                    <fo:table-cell>
                                                        <fo:block font-size="11pt" text-align="start"
                                                                  color="gray">
                                                            :
                                                            <xsl:value-of select="errorMessage" />
                                                        </fo:block>
                                                    </fo:table-cell>
                                                </fo:table-row>
                                            </xsl:when>
                                        </xsl:choose>

                                        <xsl:if test="alertMessage">
                                            <fo:table-row>
                                                <fo:table-cell padding="2pt" border="none">
                                                    <fo:block font-size="11pt" text-align="start">
                                                        Alerta
                                                    </fo:block>
                                                </fo:table-cell>
                                                <fo:table-cell>
                                                    <fo:block font-size="11pt" text-align="start" color="gray">
                                                        :
                                                        <xsl:value-of select="alertMessage" />
                                                    </fo:block>
                                                </fo:table-cell>
                                            </fo:table-row>
                                        </xsl:if>

                                    </fo:table-body>
                                </fo:table>
                            </xsl:for-each>
                        </fo:block>
                    </xsl:if>
                </xsl:for-each>
            </fo:block>
        </xsl:if>
    </xsl:template>

    <xsl:template match="certificate">

        <fo:block font-size="11pt" text-align="left" line-height="2.5"
                  font-weight="bold">
            <fo:inline>Certificado</fo:inline>
        </fo:block>

        <fo:table table-layout="fixed" width="100%" border="none"
                  text-align="center" space-after="10mm" page-break-inside="avoid">

            <fo:table-column column-width="1.9in" />
            <fo:table-column column-width="4.8in" />

            <fo:table-body>

                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" text-align="start">
                            Buscado
                        </fo:block>
                    </fo:table-cell>
                    <fo:table-cell>
                        <fo:block font-size="11pt" text-align="start" color="gray">
                            :
                            <xsl:choose>
                                <xsl:when test="online='True'">
                                    Online
                                </xsl:when>
                                <xsl:otherwise>
                                    Offline
                                </xsl:otherwise>
                            </xsl:choose>
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>

                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" text-align="start">
                            Assinatura
                        </fo:block>
                    </fo:table-cell>
                    <fo:table-cell>
                        <fo:block font-size="11pt" text-align="start" color="gray">
                            :
                            <xsl:choose>
                                <xsl:when test="validSignature='True'">
                                    Aprovada
                                </xsl:when>
                                <xsl:otherwise>
                                    Reprovada
                                </xsl:otherwise>
                            </xsl:choose>
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>

                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" text-align="start">
                            Entidade
                        </fo:block>
                    </fo:table-cell>
                    <fo:table-cell>
                        <fo:block font-size="11pt" text-align="start" color="gray">
                            :
                            <xsl:value-of select="subjectName" />
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>


                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" text-align="start">
                            Emissor
                        </fo:block>
                    </fo:table-cell>
                    <fo:table-cell>
                        <fo:block font-size="11pt" text-align="start" color="gray">
                            :
                            <xsl:value-of select="issuerName" />
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>

                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" text-align="start">
                            Data de emissão
                        </fo:block>
                    </fo:table-cell>
                    <fo:table-cell>
                        <fo:block font-size="11pt" text-align="start" color="gray">
                            :
                            <xsl:value-of select="notBefore" />
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>

                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" text-align="start">
                            Aprovado até
                        </fo:block>
                    </fo:table-cell>
                    <fo:table-cell>
                        <fo:block font-size="11pt" text-align="start" color="gray">
                            :
                            <xsl:value-of select="notAfter" />
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>

                <xsl:choose>
                    <xsl:when test="expired='True'">
                        <fo:table-row>
                            <fo:table-cell padding="2pt" border="none">
                                <fo:block font-size="11pt" text-align="start">
                                    Expirado
                                </fo:block>
                            </fo:table-cell>
                            <fo:table-cell>
                                <fo:block font-size="11pt" text-align="start" color="gray">
                                    :
                                    <xsl:choose>
                                        <xsl:when test="expired='True'">
                                            Sim
                                        </xsl:when>
                                    </xsl:choose>
                                </fo:block>
                            </fo:table-cell>
                        </fo:table-row>
                    </xsl:when>
                </xsl:choose>

                <xsl:choose>
                    <xsl:when test="revoked='True'">
                        <fo:table-row>
                            <fo:table-cell padding="2pt" border="none">
                                <fo:block font-size="11pt" text-align="start">
                                    Revogado
                                </fo:block>
                            </fo:table-cell>
                            <fo:table-cell>
                                <fo:block font-size="11pt" text-align="start" color="gray">
                                    :
                                    <xsl:choose>
                                        <xsl:when test="revoked='True'">
                                            Sim
                                        </xsl:when>
                                    </xsl:choose>
                                </fo:block>
                            </fo:table-cell>
                        </fo:table-row>
                    </xsl:when>
                </xsl:choose>
            </fo:table-body>
        </fo:table>
        <!-- LCR -->
        <xsl:if test="(crl)">
            <fo:block font-size="11pt" text-align="start" text-indent="5mm">

                <fo:block font-size="11pt" text-align="left" line-height="1.5"
                          font-weight="bold">
                    <fo:inline>LCR</fo:inline>
                </fo:block>

                <fo:block>
                    <xsl:apply-templates select="crl" />
                </fo:block>
            </fo:block>
        </xsl:if>

    </xsl:template>

    <xsl:template match="crl">

        <fo:table table-layout="fixed" width="100%" border="none"
                  text-align="center" space-after="2mm" page-break-inside="avoid">

            <fo:table-column column-width="1.9in" />
            <fo:table-column column-width="4.5in" />

            <fo:table-body>
                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" text-align="start">
                            Emissor
                        </fo:block>
                    </fo:table-cell>
                    <fo:table-cell>
                        <fo:block font-size="11pt" text-align="start" color="gray">
                            :
                            <xsl:value-of select="issuerName" />
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>

                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" text-align="start">
                            Buscado
                        </fo:block>
                    </fo:table-cell>
                    <fo:table-cell>
                        <fo:block font-size="11pt" text-align="start" color="gray">
                            :
                            <xsl:choose>
                                <xsl:when test="online='True'">
                                    Online
                                </xsl:when>
                                <xsl:otherwise>
                                    Offline
                                </xsl:otherwise>
                            </xsl:choose>
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>

                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" text-align="start">
                            Assinatura
                        </fo:block>
                    </fo:table-cell>
                    <fo:table-cell>
                        <fo:block font-size="11pt" text-align="start" color="gray">
                            :
                            <xsl:choose>
                                <xsl:when test="validSignature='True'">
                                    Aprovada
                                </xsl:when>
                                <xsl:otherwise>
                                    Reprovada
                                </xsl:otherwise>
                            </xsl:choose>
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>

                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" text-align="start">
                            Data de publicação
                        </fo:block>
                    </fo:table-cell>
                    <fo:table-cell>
                        <fo:block font-size="11pt" text-align="start" color="gray">
                            :
                            <xsl:value-of select="dates/thisUpdate" />
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>

                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" text-align="start">
                            Próxima atualização
                        </fo:block>
                    </fo:table-cell>
                    <fo:table-cell>
                        <fo:block font-size="11pt" text-align="start" color="gray">
                            :
                            <xsl:value-of select="dates/nextUpdate" />
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>

            </fo:table-body>
        </fo:table>

    </xsl:template>

    <xsl:template match="notIcpbrSignature">

        <!-- ASSINANTE -->

        <fo:table table-layout="fixed" width="100%" border="none"
                  text-align="center" space-after="0mm" page-break-inside="avoid">

            <fo:table-column column-width="1.9in" />
            <fo:table-column column-width="4.8in" />

            <fo:table-body>

                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" font-weight="bold" text-align="start">
                            Assinante
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>


                <fo:table-row>
                    <fo:table-cell padding="2pt" border="none">
                        <fo:block font-size="11pt" text-align="start">
                            Assinante
                        </fo:block>
                    </fo:table-cell>
                    <fo:table-cell>
                        <fo:block font-size="11pt" text-align="start" color="gray">
                            :
                            <xsl:value-of select="certification/signer/subjectName" />
                        </fo:block>
                    </fo:table-cell>
                </fo:table-row>
            </fo:table-body>
        </fo:table>
    </xsl:template>
</xsl:stylesheet>
