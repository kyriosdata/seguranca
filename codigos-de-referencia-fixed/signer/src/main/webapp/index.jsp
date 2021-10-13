<%@ page contentType="text/html; charset=UTF-8" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
<head>
    <link rel="shortcut icon" type="image/png" href="favicon.ico"/>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Assinador de Referência</title>
    <script src="https://code.jquery.com/jquery-3.2.1.slim.min.js"
            integrity="sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/GpGFF93hXpG5KkN"
            crossorigin="anonymous"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js"
            integrity="sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl"
            crossorigin="anonymous"></script>
    <link rel="stylesheet"
          href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css"
          integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm"
          crossorigin="anonymous">
    <link rel="stylesheet"
          href="https://fonts.googleapis.com/css?family=Open+Sans">
    <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/index.css">
    <script defer src="${pageContext.request.contextPath}/logic.js"></script>
</head>
<body>
<header>
    <a href="https://iti.gov.br/"><img id="image" src="${pageContext.request.contextPath}/logo.png" alt="logo"></a>
</header>

<!-- Navbar -->
<div id="home">
    <table>
        <tr>
            <td><a href="<c:url value="/"/>">Início</a></td>
            <td><a data-target="#faqModal" data-toggle="modal"
                   href="#faqModal">F.A.Q.</a></td>
        </tr>
    </table>
</div>
<div id="parent">
    <!-- Sobre -->
    <div id="sobrecontainer">
        <p id="sobrecontent">
            Com o Assinador de Referência, disponibilizado de forma gratuita pelo ITI, você pode assinar digitalmente seus documentos. Atualmente, é possível assinar utilizando os formatos CMS, PDF e XML. Recomenda-se o uso do navegador Google Chrome ou Mozilla Firefox.
            <br><br>
            <b>Versão ${version}.</b>
        <h2>Sobre</h2>

    </div>

    <!-- Upload dos arquivos -->
    <div id="filecontainer">
        <div>
            <form id="form" method="post" enctype="multipart/form-data" target="hidden_iframe">
                <div id="tbs_div0" class="filechoose">
                    <div id="filechooseheader">Selecione o formato e a suíte de assinatura, um ou mais arquivos para assinar, o arquivo com sua chave privada e digite a senha deste último.</div>
                    <select name="sig_pol"
                            class="selection"
                            id="sig_pol"
                            required>
                    </select>
                    <input name="sig_pol_servlet" id="sig_pol_servlet" type="text" hidden>
                    <br><br>
                    <select name="sig_policy"
                            class="selection"
                            id="sig_policy"
                            hidden>
                    </select>
                    <div id="sig_policy_blankspace" hidden><br><br></div>
                    <select name="sig_policy_version"
                            class="selection"
                            id="sig_policy_version"
                            hidden>
                    </select>
                    <div id="sig_policy_version_blankspace" hidden><br><br></div>
                    <select name="suite_sel"
                            class="selection"
                            id="suite_sel"
                            hidden>
                    </select>
                    <a href="#" data-toggle="tooltip" data-placement="top" id="suite_tooltip" hidden
                       title="Selecione o algoritmo de assinatura a ser utilizado. Este deve ser compatível com a chave privada que você usará para assinar o documento. Na dúvida, deixe este campo sem seleção.">
                        <img src="${pageContext.request.contextPath}/help-24px.png" width="24" height="24">
                    </a>
                    <div id="sig_suite_blankspace" hidden><br></div>
                    <select name="sig_format"
                            class="selection"
                            id="sig_format"
                            required
                            hidden>
                    </select>
                    <div id="sig_format_blankspace" hidden><br><br></div>
                    <input name="sig_format_servlet" id="sig_format_servlet" type="text" hidden>
                    <div id="blankspace" hidden><br></div>

                    <select name="xml_detached_select"
                            class="selection"
                            id="xml_detached_select"
                            hidden>
                    </select>
                    <div id="xml_detached_blankspace" hidden><br><br></div>

                    <div id="fileselect">
                        <input type="text" name="tbs_text_box0"
                           id="tbs_text_box0"
                           class="file"
                           placeholder="Selecione o(s) arquivo(s) a ser(em) assinado(s)..."
                           readonly="readonly"
                           multiple
                           required/>
                        <input type="file" name="file_tbs"
                           id="file_tbs"
                           multiple
                           required/>
                        <label name="sig_lbl"
                           id="sig_lbl0"
                           for="file_tbs"
                           class="select selectlbl"
                           hidden>SELECIONAR ARQUIVO(S)</label>
                        <span name="sig_span" id="sig_span0" class="siglbl" >SELECIONAR ARQUIVO(S)</span>
                        <span name="sig_span" id="sig_span1" class="siglbl" hidden>SELECIONAR ARQUIVO(S)</span>
                    </div>

                    <div id="xml_detached" hidden>
                        <input type="url"
                               name="xml_url"
                               id="xml_url"
                               class="field"
                               placeholder="URL (o XML precisa estar disponível online através de HTTP, não HTTPS)">
                    </div>
                </div>

                <hr id="divider0" hidden>

                <div>
                    <input type="text" name="certificate_text_box"
                           id="certificate_text_box"
                           class="file"
                           placeholder="Selecione arquivo de chaves e certificados..."
                           readonly="readonly"
                           required/>
                    <input type="file" name="signer_certificate"
                           id="signer_certificate"
                           accept=".p12"
                           required/>
                    <label id="sig_lbl1" for="signer_certificate" class="select selectlbl">SELECIONAR ARQUIVO</label>
                    <br><br>
                    <input type="password" name="password"
                           id="password"
                           class="password"
                           placeholder="Por favor, digite a senha do arquivo de chaves e certificados..."
                           readonly="readonly"
                           required>
                    &nbsp;<img src="${pageContext.request.contextPath}/visibility-24px.png" id="eye" width="24" height="24" onclick="togglePassword()">
                    <br><br>
                    <label id="pdf_fields" hidden>Os campos a seguir são de preenchimento opcional.</label>
                    <input type="text"
                           name="pdf_reason"
                           id="pdf_reason"
                           class="field"
                           placeholder="Por favor, digite o motivo da assinatura..."
                           hidden>
                    <div class="blankspacepdf" id="blankspacepdf0" hidden><br><br></div>
                    <input type="text"
                           name="pdf_address"
                           id="pdf_address"
                           class="field"
                           placeholder="Endereço"
                           hidden>
                    <div class="blankspacepdf" id="blankspacepdf1" hidden><br><br></div>
                    <input type="number"
                           name="pdf_cep"
                           id="pdf_cep"
                           class="field"
                           placeholder="CEP"
                           hidden>
                    <div class="blankspacepdf" id="blankspacepdf2" hidden><br><br></div>
                    <input type="text"
                           name="pdf_city"
                           id="pdf_city"
                           class="field"
                           placeholder="Cidade"
                           hidden>
                    <div class="blankspacepdf" id="blankspacepdf3" hidden><br><br></div>
                    <input type="text"
                           name="pdf_state"
                           id="pdf_state"
                           class="field"
                           placeholder="UF"
                           hidden>
                    <div class="blankspacepdf" id="blankspacepdf4" hidden><br><br></div>
                    <button id="btn_verify"
                            type="submit"
                            class="disabled"
                            disabled>
                        GERAR ASSINATURA(S)
                    </button>
                </div>
            </form>
        </div>
        <h2>ASSINADOR DE REFERÊNCIA</h2>
    </div>
</div>

<!-- Modal file malformed -->
<div class="modal fade" id="malformedFileError" role="dialog">
    <div class="modal-dialog">
        <!-- Modal content-->
        <div class="modal-content">
            <div class="modal-body">
                <p>O conteúdo de algum arquivo selecionado para ser assinado não é compatível com este tipo de assinatura.</p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">Ok</button>
            </div>
        </div>
    </div>
</div>

<!-- Modal certificate is not ICP-Brasil -->
<div class="modal fade" id="certPathError" role="dialog">
    <div class="modal-dialog">
        <!-- Modal content-->
        <div class="modal-content">
            <div class="modal-body">
                <p>Não foi possível encontrar o caminho de certificação para o certificado do assinante selecionado.
                    Por favor, selecione outro certificado.</p>
            </div>
            <div class="modal-footer">
                <button id="close_alert1" type="button" class="btn btn-default" data-dismiss="modal">Ok</button>
            </div>
        </div>
    </div>
</div>

<!-- Modal Password Error -->
<div class="modal fade" id="incorrectPassword" tabindex="-1" role="dialog" aria-labelledby="incorrectPassword" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="exampleModalLabel">Senha Incorreta</h5>
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
            </div>
            <div class="modal-body">
                A senha está incorreta. Por favor, verifique e tente novamente.
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-primary" data-dismiss="modal">Fechar</button>
            </div>
        </div>
    </div>
</div>

<!-- Modal Signature Error -->
<div class="modal fade" id="signatureError" tabindex="-1" role="dialog" aria-labelledby="signatureError" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="signatureErrorLabel">Erro na assinatura!</h5>
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
            </div>
            <div class="modal-body">
                Ocorreu um erro ao assinar o(s) documento(s) enviados. Confira se o documento se adequa aos padrões de assinatura!
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-primary" data-dismiss="modal">Fechar</button>
            </div>
        </div>
    </div>
</div>

<!-- Modal Algorithm Error -->
<div class="modal fade" id="algorithmError" tabindex="-1" role="dialog" aria-labelledby="signatureError" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="algorithmErrorLabel">Erro na assinatura!</h5>
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
            </div>
            <div class="modal-body">
                Ocorreu um erro ao assinar o(s) documento(s) enviados. Confira se o algoritmo da sua chave privada condiz com o algoritmo selecionado para assinatura!
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-primary" data-dismiss="modal">Fechar</button>
            </div>
        </div>
    </div>
</div>

<!-- FAQ Modal -->
<div class="modal fade" id="faqModal" tabindex="-1" role="dialog" aria-labelledby="faq" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="faqLabel">Perguntas Frequentes</h5>
                <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
            </div>
            <div class="modal-body">
                <p><b>P: Quais são os formatos de assinatura?</b></p>
                <p>
                    R: As assinaturas estão disponíveis em três formatos:
                    <ul>
                        <li>CMS: Com a assinatura CMS, você pode assinar digitalmente qualquer tipo de documento,
                            independente do formato do arquivo. </li>
                        <li>PDF: Aceita apenas documentos já em formato PDF. Retorna ao usuário o mesmo documento, com a
                            adição de uma assinatura digital CMS embutida.</li>
                        <li>XML: Aceita somente documentos em formato XML. Retorna ao usuário um documento XML, com os
                             bytes da assinatura dentro de uma tag própria.</li>
                    </ul>
                </p>
                <p><b>P: Quais são os modos de assinatura?</b></p>
                <p>
                    R: O usuário pode escolher entre diversos modos, a depender da disponibilidade de acordo com o
                    formato previamente escolhido:
                    <ul>
                        <li>Anexada: Os bytes da assinatura são embutidos ao final do documento</li>
                        <li>Destacada: Os bytes da assinatura são mantidos em um arquivo separado.</li>
                        <li>Envelopando: O documento retornado inteiro é a assinatura, com uma referência ao
                            objeto assinado embutida.</li>
                        <li>Internamente Destacada: A assinatura e o documento são inseridos em um nodo pai, tendo o
                        mesmo nível hierarquico.</li>
                    </ul>
                </p>
                <p><b>P: Como escolho as suítes de assinatura?</b></p>
                <p>
                    R: Você pode assinar documentos com dois tipos de chave privada: ECDSA ou RSA. A chave privada está
                    contida dentro do arquivo de certificado. <br>
                    Sabendo sua chave privada, basta decidir quantos bits você quer para o algoritmo de resumo: 256 ou 512.
                </p>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-primary" data-dismiss="modal">Fechar</button>
            </div>
        </div>
    </div>
</div>

<iframe name="hidden_iframe" id="postFrame"></iframe>
<div id="policyInfoFrame" hidden>
    <%=request.getAttribute("policyInfoJson")%>
</div>
</body>
</html>
