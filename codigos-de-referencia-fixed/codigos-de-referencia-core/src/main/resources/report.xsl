<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

    <xsl:output method="html"/>

    <xsl:template match="/">
        <table class="report-table">
            <tr>
                <th>Data de verificação</th>
                <td>
                    <xsl:value-of select="report/date/verificationDate"/>
                </td>
            </tr>
            <tr>
                <th>Versão do software</th>
                <td>
                    <xsl:value-of select="report/software/version"/>
                </td>
            </tr>
            <tr>
                <th>Nome do arquivo</th>
                <td>
                    <code>
                        <xsl:value-of select="report/software/sourceFile"/>
                    </code>
                </td>
            </tr>
        </table>
        <xsl:if test="report/pas/pa">
            <details>
                <summary>
                    Informações da LPA
                </summary>
                <table class="report-table">
                    <tr>
                        <th>Versão</th>
                        <td>
                            <xsl:value-of select="report/lpa/version"/>
                        </td>
                    </tr>
                    <tr>
                        <th>Obtida online</th>
                        <td>
                            <xsl:choose>
                                <xsl:when test="report/lpa/online='True'">
                                    Sim
                                </xsl:when>
                                <xsl:otherwise>
                                    Não
                                </xsl:otherwise>
                            </xsl:choose>
                        </td>
                    </tr>
                    <tr>
                        <th>Status da LPA</th>
                        <td>
                            <xsl:choose>
                                <xsl:when test="report/lpa/valid='True'">
                                    Aprovada
                                </xsl:when>
                                <xsl:otherwise>
                                    Reprovada
                                </xsl:otherwise>
                            </xsl:choose>
                        </td>
                    </tr>
                    <xsl:if test="report/lpa/valid='False' and report/lpa/lpaErrorMessage">
                        <th>Mensagem de erro</th>
                        <td>
                            <xsl:value-of select="report/lpa/lpaErrorMessage"/>
                        </td>
                    </xsl:if>
                    <tr>
                        <th>Próxima emissão</th>
                        <td>
                            <xsl:value-of select="report/lpa/period"/>
                        </td>
                    </tr>
                </table>
            </details>
            <details open="">
                <summary>Informações de política</summary>
                <xsl:apply-templates select="report/pas/pa"/>
            </details>
        </xsl:if>
        <xsl:apply-templates
                select="report/signatures/signature"/>
        <xsl:apply-templates
            select="report/signatures/notIcpbrSignature"/>
    </xsl:template>

    <xsl:template match="pa">
        <details>
            <summary>
                <xsl:value-of select="oid"/>
            </summary>
            <xsl:if test="contains(oid, 'PA_')">
                <table class="report-table">
                    <tr>
                        <th>Status da PA</th>
                        <td>
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
                        </td>
                    </tr>
                    <tr>
                        <th>Íntegra segundo a LPA</th>
                        <td>
                            <xsl:choose>
                                <xsl:when test="validLpa='True'">
                                    Sim
                                </xsl:when>
                                <xsl:otherwise>
                                    Não
                                </xsl:otherwise>
                            </xsl:choose>
                        </td>
                    </tr>
                    <tr>
                        <th>Íntegra</th>
                        <td>
                            <xsl:choose>
                                <xsl:when test="valid='True'">
                                    Sim
                                </xsl:when>
                                <xsl:otherwise>
                                    Não
                                </xsl:otherwise>
                            </xsl:choose>
                        </td>
                    </tr>
                    <tr>
                        <xsl:choose>
                            <xsl:when test="not(period='')">
                                <th>Aprovada no período</th>
                                <td>
                                    <xsl:value-of select="period"/>
                                </td>
                            </xsl:when>
                        </xsl:choose>
                    </tr>
                </table>
            </xsl:if>
            <xsl:if test="not(error = '')">
                <table class="report-table">
                    <tr>
                        <th>Mensagem de erro</th>
                        <td>
                            <xsl:value-of select="error"/>
                        </td>
                    </tr>
                </table>
            </xsl:if>
        </details>
    </xsl:template>

    <xsl:template match="signature">
        <details open="">
            <summary>
                Assinatura por
                <xsl:value-of
                        select="certification/signer/subjectName"/>
            </summary>
            <details open="">
                <summary>Informações da assinatura</summary>
                <table class="report-table">
                    <tr>
                        <th>Status da assinatura</th>
                        <td>
                            <xsl:value-of
                                    select="certification/signer/validSignature"/>
                        </td>
                    </tr>
                    <tr>
                        <th>Caminho de certificação</th>
                        <td>
                            <xsl:choose>
                                <xsl:when
                                        test="certification/signer/certPathValid='Valid'">
                                    Aprovado
                                </xsl:when>
                                <xsl:when
                                        test="certification/signer/certPathValid='Revoked'">
                                    Revogado
                                </xsl:when>
                                <xsl:when
                                        test="certification/signer/certPathValid='Expired'">
                                    Expirado
                                </xsl:when>
                                <xsl:when
                                        test="certification/signer/certPathValid='NotValidYet'">
                                    Ainda não validado
                                </xsl:when>
                                <xsl:when
                                        test="certification/signer/certPathValid='Unknown'">
                                    Desconhecido
                                </xsl:when>
                                <xsl:otherwise>
                                    Reprovado
                                </xsl:otherwise>
                            </xsl:choose>
                        </td>
                    </tr>
                    <xsl:choose>
                        <xsl:when
                                test="certification/signer/certPathMessage != ''">
                            <tr>
                                <th>Mensagem de erro</th>
                                <td>
                                    <xsl:value-of
                                            select="certification/signer/certPathMessage"/>
                                </td>
                            </tr>
                        </xsl:when>
                    </xsl:choose>
                    <xsl:if test="contains(signaturePolicy, 'PA_')">
                        <tr>
                            <th>Política utilizada</th>
                            <td>
                                <xsl:value-of select="signaturePolicy"/>
                            </td>
                        </tr>
                    </xsl:if>
                    <tr>
                        <th>Estrutura da assinatura</th>
                        <td>
                            <xsl:choose>
                                <xsl:when test="integrity/schema='True'">
                                    Em conformidade com o padrão
                                </xsl:when>
                                <xsl:when test="integrity/schema='Unknown'">
                                    Impossível determinar.
                                    <xsl:value-of
                                            select="integrity/schemaMessage"/>
                                    <br/>
                                </xsl:when>
                                <xsl:otherwise>
                                    Não está em conformidade com o padrão
                                    <xsl:value-of
                                            select="integrity/schemaMessage"/>
                                    <br/>
                                </xsl:otherwise>
                            </xsl:choose>
                        </td>
                    </tr>
                    <tr>
                        <th>Cifra assimétrica</th>
                        <td>
                            <xsl:choose>
                                <xsl:when
                                        test="integrity/asymmetricCipher='True'">
                                    Aprovada
                                </xsl:when>
                                <xsl:otherwise>
                                    Reprovada
                                </xsl:otherwise>
                            </xsl:choose>
                        </td>
                    </tr>
                    <tr>
                        <th>Resumo criptográfico</th>
                        <td>
                            <xsl:choose>
                                <xsl:when test="integrity/hash='True'">
                                    Correto
                                </xsl:when>
                                <xsl:otherwise>
                                    Incorreto
                                </xsl:otherwise>
                            </xsl:choose>
                        </td>
                    </tr>
                    <xsl:if test="(attributes/requiredAttributes/requiredAttribute)">
                        <tr>
                            <th>Atributos obrigatórios</th>
                            <td>
                                <xsl:choose>
                                    <xsl:when test="attributeValid='True'">
                                        Aprovados
                                    </xsl:when>
                                    <xsl:otherwise>
                                        Existe ao menos um atributo obrigatório
                                        reprovado
                                    </xsl:otherwise>
                                </xsl:choose>
                            </td>
                        </tr>
                    </xsl:if>
                    <xsl:if test="paRules/mandatedCertificateInfo != ''">
                        <tr>
                            <th>Certificados necessários</th>
                            <td>
                                <xsl:value-of
                                        select="paRules/mandatedCertificateInfo"/>
                            </td>
                        </tr>
                    </xsl:if>
                    <xsl:if test="(errorMessages/errorMessage)">
                        <xsl:for-each select="errorMessages/errorMessage">
                            <tr>
                                <xsl:choose>
                                    <xsl:when test="position()=1">
                                        <th>Mensagem de erro</th>
                                    </xsl:when>
                                    <xsl:otherwise>
                                        <th></th>
                                    </xsl:otherwise>
                                </xsl:choose>
                                <td><xsl:value-of select="."/></td>
                            </tr>
                        </xsl:for-each>
                    </xsl:if>
                </table>
            </details>
            <details>
                <summary>Caminho de certificação</summary>
                <xsl:apply-templates select="certification/signer/certificate"/>
            </details>
            <xsl:if test="(attributes/requiredAttributes/requiredAttribute) or (attributes/optionalAttributes/optionalAttribute)">
                <details>
                    <summary>Atributos</summary>
                    <xsl:if test="(attributes/requiredAttributes/requiredAttribute)">
                        <details>
                            <summary>
                                Atributos obrigatórios
                            </summary>
                            <table class="report-table">
                                <xsl:for-each
                                        select="attributes/requiredAttributes/requiredAttribute">
                                    <tr>
                                        <th>
                                            <xsl:value-of select="name"/>
                                        </th>
                                        <td>
                                            <xsl:choose>
                                                <xsl:when test="error='False'">
                                                    Aprovado
                                                </xsl:when>
                                                <xsl:when
                                                        test="error='Not validated'">
                                                    Não verificado
                                                    <xsl:if test="not(errorMessage='')">
                                                        . <xsl:value-of
                                                            select="errorMessage"/>
                                                    </xsl:if>
                                                </xsl:when>
                                                <xsl:when test="error='True'">
                                                    Reprovado. <xsl:value-of
                                                        select="errorMessage"/>
                                                </xsl:when>
                                                <xsl:otherwise>
                                                    Reprovado
                                                </xsl:otherwise>
                                            </xsl:choose>
                                            <xsl:if test="alertMessage">
                                                . Alerta: <xsl:value-of
                                                    select="alertMessage"/>
                                            </xsl:if>
                                            <br/>
                                        </td>
                                    </tr>
                                </xsl:for-each>
                            </table>
                        </details>
                    </xsl:if>
                    <xsl:if test="(attributes/optionalAttributes/optionalAttribute)">
                        <details>
                            <summary>
                                Atributos opcionais
                            </summary>
                            <table class="report-table">
                                <xsl:for-each
                                        select="attributes/optionalAttributes/optionalAttribute">
                                    <tr>
                                        <th>
                                            <xsl:value-of select="name"/>
                                        </th>
                                        <td>
                                            <xsl:choose>
                                                <xsl:when test="error='False'">
                                                    Aprovado
                                                </xsl:when>
                                                <xsl:when
                                                        test="error='Not validated'">
                                                    Não verificado
                                                    <xsl:if test="not(errorMessage='')">
                                                        . <xsl:value-of
                                                            select="errorMessage"/>
                                                    </xsl:if>
                                                </xsl:when>
                                                <xsl:when test="error='True'">
                                                    Reprovado. <xsl:value-of
                                                        select="errorMessage"/>
                                                </xsl:when>
                                                <xsl:otherwise>
                                                    Reprovado
                                                </xsl:otherwise>
                                            </xsl:choose>
                                            <xsl:if test="alertMessage">
                                                . Alerta: <xsl:value-of
                                                    select="alertMessage"/>
                                            </xsl:if>
                                            <br/>
                                        </td>
                                    </tr>
                                </xsl:for-each>
                            </table>
                        </details>
                    </xsl:if>
                </details>
            </xsl:if>

            <xsl:if test="counterSignatures">
                <details>
                    <summary>Contra assinaturas</summary>
                    <xsl:apply-templates
                            select="counterSignatures/signature"/>
                </details>
            </xsl:if>

            <xsl:if test="(certification/timeStamps/timeStamp)">
                <details>
                    <summary>Carimbos de tempo</summary>
                    <xsl:apply-templates
                            select="certification/timeStamps/timeStamp"/>
                </details>
            </xsl:if>
        </details>
    </xsl:template>

    <xsl:template match="notIcpbrSignature">
        <summary class="notIcpbrSummary">
            Assinatura por
            <xsl:value-of
                    select="certification/signer/subjectName"/>
        </summary>
    </xsl:template>

    <xsl:template match="timeStamp">
        <details>
            <summary>
                <xsl:value-of select="timeStampIdentifier"/>
            </summary>
            <details>
                <summary>Informações do carimbo</summary>
                <table class="report-table">
                    <tr>
                        <th>Assinante</th>
                        <td>
                            <xsl:value-of select="timeStampName"/>
                        </td>
                    </tr>
                    <tr>
                        <th>Data do carimbo</th>
                        <td>
                            <xsl:value-of select="timeStampTimeReference"/>
                        </td>
                    </tr>
                    <tr>
                        <th>Caminho de certificação</th>
                        <td>
                            <xsl:choose>
                                <xsl:when
                                        test="certPathValid='Valid'">
                                    Aprovado
                                </xsl:when>
                                <xsl:when
                                        test="certPathValid='Revoked'">
                                    Revogado
                                </xsl:when>
                                <xsl:when
                                        test="certPathValid='Expired'">
                                    Expirado
                                </xsl:when>
                                <xsl:when
                                        test="certPathValid='NotValidYet'">
                                    Ainda não validado
                                </xsl:when>
                                <xsl:when
                                        test="certPathValid='Unknown'">
                                    Desconhecido
                                </xsl:when>
                                <xsl:otherwise>
                                    Reprovado
                                </xsl:otherwise>
                            </xsl:choose>
                        </td>
                    </tr>
                    <xsl:choose>
                        <xsl:when
                                test="certification/signer/certPathMessage != ''">
                            <tr>
                                <th>Mensagem de erro</th>
                                <td>
                                    <xsl:value-of
                                            select="certification/signer/certPathMessage"/>
                                </td>
                            </tr>
                        </xsl:when>
                    </xsl:choose>
                    <tr>
                        <th>Estrutura da assinatura</th>
                        <td>
                            <xsl:choose>
                                <xsl:when test="integrity/schema='True'">
                                    Em conformidade com o padrão
                                </xsl:when>
                                <xsl:when test="integrity/schema='Unknown'">
                                    Impossível determinar.
                                    <xsl:value-of
                                            select="integrity/schemaMessage"/>
                                    <br/>
                                </xsl:when>
                                <xsl:otherwise>
                                    Não está em conformidade com o padrão
                                    <xsl:value-of
                                            select="integrity/schemaMessage"/>
                                    <br/>
                                </xsl:otherwise>
                            </xsl:choose>
                        </td>
                    </tr>
                    <tr>
                        <th>Cifra assimétrica</th>
                        <td>
                            <xsl:choose>
                                <xsl:when
                                        test="integrity/asymmetricCipher='True'">
                                    Aprovada
                                </xsl:when>
                                <xsl:otherwise>
                                    Reprovada
                                </xsl:otherwise>
                            </xsl:choose>
                        </td>
                    </tr>
                    <tr>
                        <th>Resumo criptográfico</th>
                        <td>
                            <xsl:choose>
                                <xsl:when test="integrity/hash='True'">
                                    Correto
                                </xsl:when>
                                <xsl:otherwise>
                                    Incorreto
                                </xsl:otherwise>
                            </xsl:choose>
                        </td>
                    </tr>
                    <xsl:if test="(attributes/requiredAttributes/requiredAttribute)">
                        <tr>
                            <th>Atributos obrigatórios</th>
                            <td>
                                <xsl:choose>
                                    <xsl:when test="attributeValid='True'">
                                        Aprovados
                                    </xsl:when>
                                    <xsl:otherwise>
                                        Existe ao menos um atributo obrigatório
                                        reprovado
                                    </xsl:otherwise>
                                </xsl:choose>
                            </td>
                        </tr>
                    </xsl:if>
                </table>
            </details>
            <details>
                <summary>Caminho de certificação</summary>
                <xsl:apply-templates select="certificate"/>
            </details>
            <xsl:if test="(attributes/requiredAttributes/requiredAttribute) or (attributes/optionalAttributes/optionalAttribute)">
                <details>
                    <summary>Atributos</summary>
                    <xsl:if test="(attributes/requiredAttributes/requiredAttribute)">
                        <details>
                            <summary>
                                Atributos obrigatórios
                            </summary>
                            <table class="report-table">
                                <xsl:for-each
                                        select="attributes/requiredAttributes/requiredAttribute">
                                    <tr>
                                        <th>
                                            <xsl:value-of select="name"/>
                                        </th>
                                        <td>
                                            <xsl:choose>
                                                <xsl:when test="error='False'">
                                                    Aprovado
                                                </xsl:when>
                                                <xsl:when
                                                        test="error='Not validated'">
                                                    Não verificado
                                                    <xsl:if test="not(errorMessage='')">
                                                        . <xsl:value-of
                                                            select="errorMessage"/>
                                                    </xsl:if>
                                                </xsl:when>
                                                <xsl:when test="error='True'">
                                                    Reprovado. <xsl:value-of
                                                                select="errorMessage"/>
                                                </xsl:when>
                                                <xsl:otherwise>
                                                    Reprovado
                                                </xsl:otherwise>
                                            </xsl:choose>
                                            <xsl:if test="alertMessage">
                                                . Alerta: <xsl:value-of
                                                    select="alertMessage"/>
                                            </xsl:if>
                                            <br/>
                                        </td>
                                    </tr>
                                </xsl:for-each>
                            </table>
                        </details>
                    </xsl:if>
                    <xsl:if test="(attributes/optionalAttributes/optionalAttribute)">
                        <details>
                            <summary>
                                Atributos opcionais
                            </summary>
                            <table class="report-table">
                                <xsl:for-each
                                        select="attributes/optionalAttributes/optionalAttribute">
                                    <tr>
                                        <th>
                                            <xsl:value-of select="name"/>
                                        </th>
                                        <td>
                                            <xsl:choose>
                                                <xsl:when test="error='False'">
                                                    Aprovado
                                                </xsl:when>
                                                <xsl:when
                                                        test="error='Not validated'">
                                                    Não verificado
                                                    <xsl:if test="not(errorMessage = '')">
                                                        . <xsl:value-of
                                                            select="errorMessage"/>
                                                    </xsl:if>
                                                </xsl:when>
                                                <xsl:when test="error='False'">
                                                    Reprovado. <xsl:value-of
                                                        select="errorMessage"/>
                                                </xsl:when>
                                                <xsl:otherwise>
                                                    Reprovado
                                                </xsl:otherwise>
                                            </xsl:choose>
                                            <xsl:if test="alertMessage">
                                                . Alerta: <xsl:value-of
                                                    select="alertMessage"/>
                                            </xsl:if>
                                            <br/>
                                        </td>
                                    </tr>
                                </xsl:for-each>
                            </table>
                        </details>
                    </xsl:if>
                </details>
            </xsl:if>
        </details>
    </xsl:template>

    <xsl:template match="certificate">
        <details>
            <summary>
                <xsl:value-of select="subjectName"/>
            </summary>
            <table class="report-table">
                <tr>
                    <th>Emissor</th>
                    <td>
                        <xsl:value-of select="issuerName"/>
                    </td>
                </tr>
                <tr>
                    <th>Assinatura</th>
                    <td>
                        <xsl:choose>
                            <xsl:when test="validSignature='True'">
                                Aprovada
                            </xsl:when>
                            <xsl:otherwise>
                                Reprovada
                            </xsl:otherwise>
                        </xsl:choose>
                    </td>
                </tr>
                <tr>
                    <th>Obtido</th>
                    <td>
                        <xsl:choose>
                            <xsl:when test="online='True'">
                                Online
                            </xsl:when>
                            <xsl:otherwise>
                                Offline
                            </xsl:otherwise>
                        </xsl:choose>
                    </td>
                </tr>
                <tr>
                    <th>Aprovado a partir de</th>
                    <td>
                        <xsl:value-of select="notBefore"/>
                    </td>
                </tr>
                <tr>
                    <th>Aprovado até</th>
                    <td>
                        <xsl:value-of select="notAfter"/>
                    </td>
                </tr>
            </table>

            <xsl:if test="crl">
                <xsl:apply-templates select="crl"/>
            </xsl:if>
        </details>
    </xsl:template>

    <xsl:template match="crl">
        <details>
            <summary>Listas de certificados revogados</summary>
            <table class="report-table">
                <tr>
                    <th>Assinatura</th>
                    <td>
                        <xsl:choose>
                            <xsl:when test="validSignature='True'">
                                Aprovada
                            </xsl:when>
                            <xsl:otherwise>
                                Reprovada
                            </xsl:otherwise>
                        </xsl:choose>
                    </td>
                </tr>
                <tr>
                    <th>Obtida</th>
                    <td>
                        <xsl:choose>
                            <xsl:when test="online='True'">
                                Online
                            </xsl:when>
                            <xsl:otherwise>
                                Offline
                            </xsl:otherwise>
                        </xsl:choose>
                    </td>
                </tr>
                <tr>
                    <th>Data de publicação</th>
                    <td>
                        <xsl:value-of select="dates/thisUpdate"/>
                    </td>
                </tr>
                <tr>
                    <th>Próxima atualização</th>
                    <td>
                        <xsl:value-of select="dates/nextUpdate"/>
                    </td>
                </tr>
            </table>
        </details>
    </xsl:template>

</xsl:stylesheet>
