<%@ page contentType="text/html; charset=UTF-8" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<!DOCTYPE html>
<html>
<head>
    <link rel="shortcut icon" type="image/png" href="favicon.ico"/>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Verificador de Conformidade</title>
    <script src="https://code.jquery.com/jquery-3.2.1.slim.min.js"
            integrity="sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/GpGFF93hXpG5KkN"
            crossorigin="anonymous"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js"
            integrity="sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl"
            crossorigin="anonymous"></script>
    <script src="https://servicos.iti.gov.br/client.min.js"></script>
    <script src="https://servicos.iti.gov.br/aviso.min.js"></script>
    <link rel="stylesheet"
          href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css"
          integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm"
          crossorigin="anonymous">
    <link rel="stylesheet"
          href="https://fonts.googleapis.com/css?family=Open+Sans">
    <link rel="stylesheet" type="text/css" href="index.css">
    <script defer src="reportLogic.js"></script>
</head>
<body>
<header>
    <a href="http://iti.gov.br/"><img id="image" src="logo.png" alt="logo"></a>
</header>

<!-- Navbar -->
<div id="home">
    <table>
        <tr>
            <td><a href="${pageContext.request.contextPath}">Início</a></td>
            <td><a data-target="#termosModal" data-toggle="modal"
                   href="#termosModal">Termos de uso</a></td>
            <td><a data-target="#faqModal" data-toggle="modal"
                   href="#faqModal">F.A.Q.</a></td>
        </tr>
    </table>
</div>

<!-- Modal no certificate -->
<div class="modal fade" id="no_certificate_installed" role="dialog">
    <div class="modal-dialog">

        <!-- Modal content-->
        <div class="modal-content">
            <div class="modal-body">
                <p>O erro apontado é decorrente do não reconhecimento da cadeia de certificação ICP-Brasil pelo  seu navegador. Para prosseguir, instale a <a href="https://www.gov.br/iti/pt-br/assuntos/repositorio/certificados-das-acs-da-icp-brasil-arquivo-unico-compactado" target="_blank">cadeia de certificados ICP-Brasil</a>.</p>
            </div>
            <div class="modal-footer">
                <button id="close_alert3" type="button" class="btn btn-default" data-dismiss="modal">Ok</button>
            </div>
        </div>

    </div>
</div>

<!-- Modal F.A.Q -->
<div class="modal fade" id="faqModal" tabindex="-1" role="dialog"
     aria-labelledby="exampleModalLabel" aria-hidden="true">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="faqlabel">Perguntas
                    Frequentes</h5>
                <button type="button" class="close" data-dismiss="modal"
                        aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
            </div>
            <div class="modal-body">
                <b>1. Para que serve o Verificador de Conformidade?</b>
                <br>Para atestar se um arquivo assinado com certificado
                ICP-Brasil está em conformidade com o DOC-ICP-15.<br><br>
                <b>2. Como uso o verificador?</b>
                <br>Submeta a assinatura e o arquivo assinado (se aplicável)
                nos campos correspondentes e clique em <b>VERIFICAR
                CONFORMIDADE</b>.<br><br>
                <b>3. Quais as extensões dos arquivos que devo submeter?</b>
                <br>É <u>recomendado</u> que os arquivos com assinaturas
                digitais ICP-Brasil sejam gerados com as extensões
                <code>.p7s</code>, <code>.xml</code> e <code>.pdf</code>.
                Entretanto, o software tentará verificar qualquer tipo de
                arquivo independente de extensão, caso detecte que o mesmo
                contém uma assinatura digital.<br><br>
                <b>4. O que é uma assinatura digital ICP-Brasil?</b>
                <br>É a assinatura eletrônica que:
                <br>a) esteja associada inequivocamente a um par de chaves
                criptográficas que permita identificar o signatário;
                <br>b) seja produzida por dispositivo seguro de criação de
                assinatura;
                <br>c) esteja vinculada ao documento eletrônico a que diz
                respeito, de tal modo que qualquer alteração subsequente neste
                seja plenamente detectável;
                <br>d) esteja baseada em um certificado ICP-Brasil, válido à
                época da sua aposição.<br><br>
                <b>5. O que é uma assinatura anexada (<i>attached</i>)?</b>
                <br>É quando o documento assinado está anexado na assinatura
                digital.<br><br>
                <b>6. O que é uma assinatura destacada (<i>detached</i>)?</b>
                <br>É quando o documento assinado está separado da assinatura
                digital. Portanto, há dois arquivos, o documento assinado e a
                assinatura digital.<br><br>
                <b>7. O que são os formatos de assinatura CAdES, XAdES e
                    PAdES?</b>
                <br>CAdES (CMS Advanced Electronic Signatures) é um conjunto
                de extensões para o arquivo de assinatura CMS (Cryptographic
                Message Syntax), tornando-o adequado para assinaturas digitais
                avançadas.
                <br>XAdES (XML Advanced Electronic Signatures) é um conjunto
                de extensões para a sintaxe XML-DSig, tornando-a adequada para
                assinaturas digitais avançadas.
                <br>PAdES (PDF Advanced Electronic Signatures) é um conjunto
                de extensões e restrições para o formato de arquivo PDF,
                tornando-o adequado para assinaturas digitais avançadas.<br>
            </div>
        </div>
    </div>
</div>
<%--Terms of use pop up--%>
<!-- Modal -->
<div class="modal fade bd-example-modal-lg" id="termosModal" tabindex="-1" role="dialog" aria-labelledby="termsOfUseModalTitle" aria-hidden="true" data-backdrop="static" data-keyboard="false">
    <div class="modal-dialog modal-lg">
        <div class="modal-content" id="modal-content">
            <div class="modal-header">
            </div>
            <div id="longmodal-body" class="modal-body">
                <p>
                    <b>Termo de Responsabilidade e de Uso do Verificador de Conformidade</b>
                    <br/>
                    <br/>
                    O Verificador de Conformidade do Padrão de Assinatura Digital da Infraestrutura
                    de Chaves Públicas Brasileira – ICP-Brasil objetiva aferir a conformidade de
                    assinaturas digitais existentes em um arquivo assinado em relação à
                    regulamentação da ICP-Brasil e com as definições contidas na Medida Provisória
                    no 2.200-2, de 24 de agosto de 2001, que instituiu a ICP-Brasil.
                    <br/>
                    <br/>
                    Esse Verificador de Conformidade se destina à comunidade e organizações
                    públicas e privadas que desenvolvem aplicativos geradores de assinatura digital
                    para auxiliar na verificação da conformidade de arquivos assinados, resultantes
                    de seus códigos, em conformidade com as especificações regulamentadas na
                    ICP-Brasil.
                    <br/>
                    <br/>
                    Assinaturas com certificados digitais de outras infraestruturas que não seja
                    ICP-Brasil não são objetos alvos desse verificador e serão recusados para verificação.
                    <br/>
                    <br/>
                    São passíveis de verificação os arquivos produzidos nos formatos CAdES, XAdES
                    e PAdES, nas modalidades embarcadas ou destacadas, previstos no DOC-ICP-15,
                    documento que traz uma visão geral sobre assinaturas digitais, define os
                    principais conceitos e lista os demais documentos que compõem as normas da
                    ICP-Brasil sobre o assunto.
                    <br/>
                    <br/>
                    Importante destacar que no estrito propósito de efetuar a verificação da
                    conformidade de assinaturas digitais, o Verificador de Conformidade não se
                    estende a conferir elementos que não se inserem na cobertura da parte
                    assinada ou que se insere mas visualmente não sejam percebidos ou ainda
                    que possam sofrer alterações externas não cobertas pela assinatura digital.
                    <br/>
                    <br/>
                    O resultado bem-sucedido da verificação de arquivo assinado digitalmente com
                    certificado ICP-Brasil, quando submetido ao Verificador de Conformidade,
                    resultará nas seguintes situações: Aprovado, Reprovado ou Indeterminado, em
                    conformidade com a norma ETSI EN 319 102-1 V1.1.1. (2016-05), sendo:
                    <br/>
                    <br/>
                    <b>Aprovado</b> : assinatura em conformidade com a regulamentação da ICP-Brasil;
                    <br/>
                    <b>Reprovado</b>: assinatura não mantém conformidade com a regulamentação da ICP
                    Brasil;
                    <br/>
                    <b>Indeterminado</b>: informações disponíveis são insuficientes para
                    afirmar se a assinatura está em conformidade ou não com as
                    regulamentações da ICP-Brasil.
                    <br/>
                    <br/>
                    Eventuais resultados adversos ao submissor devem ser tratados com o
                    responsável pela geração do arquivo e entidades intervenientes na assinatura
                    digital, não necessariamente implicando que o arquivo assinado digitalmente seja aprovado ou reprovado
                    ou que as declarações nele constantes e seu signatário sejam verdadeiros ou não.
                    <br/>
                    <br/>
                    O ITI procura reduzir ao mínimo os inconvenientes causados por falhas técnicas.
                    No entanto, não podemos garantir um serviço sem interrupções ou perturbações
                    e eventuais indisponibilidades do Verificador de Conformidade poderão ocorrer
                    sem aviso prévio e sem a necessidade de justificativa de motivos e prazos, não se
                    responsabilizando pela eventual ocorrência.
                    <br/>
                    <br/>
                    <b>Proteção de dados pessoais</b>
                    <br/>
                    <br/>
                    O Verificador de Conformidade não armazena quaisquer informações constantes
                    em arquivos submetidos para verificação, não se responsabilizando pelo seu
                    conteúdo ou comprometimentos que dele resulte.
                    <br/>
                    <br/>
                    <b>Garantias</b>
                    <br/>
                    <br/>
                    O Instituto Nacional de Tecnologia da Informação - ITI, como provedor do serviço,
                    se isenta de garantias expressas ou tácitas, incluindo, sem limitações, quaisquer
                    garantias implícitas de comerciabilidade relacionada ao arquivo contendo
                    assinatura digital submetido ao Verificador de Conformidade.
                    <br/>
                    <br/>
                    O usuário que aceita este termo fica ciente da forma como o Verificador de
                    Conformidade se apresenta, independente da versão disponibilizada, não
                    podendo reclamar por falhas ou falta de função, sendo que qualquer pedido de
                    correção devidamente evidenciada poderá ser encaminhado ao ITI, que fará
                    análises, sem, entretanto, garantir a alteração ou prestação de suporte técnico.
                    <br/>
                    <br/>
                    <b>Responsabilidades</b>
                    <br/>
                    <br/>
                    Em nenhuma hipótese o ITI será responsável por quaisquer danos, diretos,
                    indiretos, incidentais, especiais, exemplares ou consequentes, (incluindo, sem
                    limitação, fornecimento de bens ou serviços substitutos, perda de uso ou dados,
                    lucros cessantes, ou interrupção de atividades), causados por quaisquer motivos
                    e sob qualquer teoria de responsabilidade, seja responsabilidade contratual,
                    restrita, ilícito civil, ou qualquer outra, como decorrência de uso do Verificador
                    de Conformidade, mesmo que tenham sido avisados da possibilidade de tais
                    danos.
                    <br/>
                    <br/>
                    O Verificador de Conformidade se destina ao uso aberto e livre de ônus tanto
                    para pessoas físicas quanto para pessoas jurídicas, não implicando em
                    compromisso ou vínculo comercial entre as entidades envolvidas.
                    <br/>
                    <br/>
                    Ao aceitar este Termo de Responsabilidade e de Uso, o usuário aceita que a responsabilidade do ITI pelos danos causados pela utilização ou pelo uso
                    inadequado do Verificador de Conformidade fica limitado nesse item.
                    <br/>
                    <br/>
                    O ITI resguarda-se no direito de propor quaisquer ações cíveis, penais e
                    administrativas relacionadas ao não cumprimento do disposto nesse Termo de
                    Responsabilidade e de Uso do Verificador de Conformidade, elegendo-se, desde
                    já, o foro federal da cidade de Brasília-DF, em detrimento de qualquer outro, por
                    mais especial que seja.
                    <br/>
                    <br/>
                    O ITI se reserva o direito de alterar o presente Termo de Responsabilidade e de
                    Uso do Verificador de Conformidade a qualquer momento sem prévio aviso.
            </div>
            <div class="modal-footer">
                <button type="button" id="termos-modal-close-bnt" class="btn btn-success" data-dismiss="modal"> Fechar </button>
            </div>
        </div>
    </div>
</div>

<!-- Relatório -->
<div id="reportcontainer">
    <h2>Relatório</h2>
    <c:set var="endSignatures" value="${numOfSignatures - 1}"/>
    <c:if test = "${endSignatures < 0}">
        <c:set var="endSignatures" value="${0}"/>
    </c:if>
    <c:forEach begin="0" end="${endSignatures}" var="i">
        <c:set var="report" value="report${i}"/>
        <c:set var="signatureValidity" value="signatureValidity${i}"/>
        <c:set var="signatureValidityAttr" value="signatureValidityAttr${i}"/>
        <details open=""
                 class="signature-${sessionScope[signatureValidity]}">
            <summary>RELATÓRIO ${i + 1} - Arquivo de assinatura
                    ${sessionScope[signatureValidityAttr]}</summary>
                ${sessionScope[report]}
        </details>
        <hr class="divider">
    </c:forEach>
</div>
</body>
<div class="floater">
    <button class="btnFloating"
            class="iti-svc-trigger"
            onclick="avalie()">
        Avalie este Serviço
    </button>
    <br class="mobile-hide">
    <button class="btnFloating" id="btnExpandHideAllDetails">Expandir<br/>elementos</button>
</div>
</html>
