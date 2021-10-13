package br.ufsc.labsec.signature.conformanceVerifier;

import br.ufsc.labsec.component.AbstractComponentConfiguration;
import br.ufsc.labsec.component.Component;
import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.conformanceVerifier.report.Report;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.TrustAnchorComponent;

import jakarta.servlet.http.*;
import org.apache.commons.io.IOUtils;
import org.json.XML;
import org.json.JSONObject;
import org.apache.fop.apps.Fop;
import org.apache.fop.apps.FopFactory;
import org.apache.fop.apps.FOPException;
import org.apache.fop.apps.MimeConstants;
import org.apache.pdfbox.io.MemoryUsageSetting;
import org.apache.pdfbox.multipdf.PDFMergerUtility;
import org.w3c.dom.Document;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.sax.SAXResult;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

/**
 * Servlet que engloba métodos comuns ao tratamento de relatórios.
 */
public class ReportServlet extends HttpServlet {

    protected final Charset UTF8_CHARSET = StandardCharsets.UTF_8;

    /**
     * Transforma o Report em uma String no formato JSON
     * @param r o Report a ser transformado
     * @return o Report em uma String no formato JSON
     */
    String reportToJsonString(Report r) {
        try {
            String reportString = reportToXmlString(r);
            JSONObject xmlJSONObj = XML.toJSONObject(reportString);
            return xmlJSONObj.toString(4);
        } catch (Exception e) {
            throw new RuntimeException("Error converting to String", e);
        }
    }

    /**
     * Transforma o Report em uma String no formato XML
     * @param r o Report a ser transformado
     * @return o Report em uma String no formato XML
     */
    String reportToXmlString(Report r) {
        return docToString(r.generate());
    }

    /**
     * Transforma o Document em uma String no formato JSON
     * @param document o Document a ser transformado
     * @return o Document em uma String no formato JSON
     */
    String docToString(Document document) {
        try {
            StringWriter sw = new StringWriter();
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, UTF8_CHARSET.name());
            transformer.transform(new DOMSource(document), new StreamResult(sw));
            return sw.toString();
        } catch (Exception e) {
            throw new RuntimeException("Error converting Document to String", e);
        }
    }

    /**
     * Retorna relatórios de verificação em um único arquivo PDF
     * @param app a aplicação do Verificador de Conformidade
     * @param reportList a lista de relatórios de verificação
     * @param response representa a resposta HTTP
     * @param request representa a requisição HTTP
     * @throws TransformerException
     * @throws IOException
     * @throws FOPException
     */
    void generatePDFReports(Application app, List<Report> reportList, HttpServletResponse response,
                            HttpServletRequest request)
            throws TransformerException, IOException, FOPException {
        Component csc = app.getComponent(CadesSignatureComponent.class.getName());
        String xslPath = app.getComponentParam(csc, "reportStylePathPDF");
        Source xslt = new StreamSource(Application.class.getResourceAsStream("/" + xslPath));
        PDFMergerUtility pmu = new PDFMergerUtility();
        Transformer t = TransformerFactory.newInstance().newTransformer(xslt);

        for (int i = 0; i < reportList.size(); ++i) {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            Report r = reportList.get(i);
            String signature_text_i = request.getParameter("signature_text_box" + i);
            r.setNumber(i+1);
            DOMSource d = new DOMSource(r.generate());
            Fop fop = FopFactory.newInstance().newFop(MimeConstants.MIME_PDF, os);

            // Reutiliza o texto de validade do HTML
            String validity = signatureValidityText(r);
            validity = validity.replaceAll("<b>","");
            validity = validity.replaceAll("</b>","");
            validity = validity.replaceAll("<u>","");
            validity = validity.replaceAll("</u>","");
            t.setParameter("signatureValidityAttr", validity);

            t.transform(d, new SAXResult(fop.getDefaultHandler()));
            pmu.addSource(new ByteArrayInputStream(os.toByteArray()));
        }

        ByteArrayOutputStream reportStream = new ByteArrayOutputStream();
        pmu.setDestinationStream(reportStream);
        pmu.mergeDocuments(MemoryUsageSetting.setupMainMemoryOnly());

        OutputStream out = response.getOutputStream();

        Cookie cookie = new Cookie("downloadChecker", "sent");
        cookie.setMaxAge(3);

        response.setContentType("application/pdf");
        response.setContentLength(reportStream.toByteArray().length);
        response.addCookie(cookie);
        out.write(reportStream.toByteArray());
        out.close();
    }

    /**
     * Verifica se as assinaturas da lista são todas válidas
     * @param signatures a lista de assinaturas
     * @return Um SignatureValidity que indica a validade do conjunto de assinaturas
     */
    protected SignatureReport.SignatureValidity signatureValidity(List<SignatureReport> signatures) {
        String status = Report.generateGeneralStatus(signatures);

        if (status.equals("Aprovado")) {
            return SignatureReport.SignatureValidity.Valid;
        } else if (status.equals("Indeterminado")) {
            return SignatureReport.SignatureValidity.Indeterminate;
        } else {
            return SignatureReport.SignatureValidity.Invalid;
        }
    }

    /**
     * Cria a string da validade do arquivo. Reflete a validade do documento
     * e todas as suas assinaturas
     * @param report o relatório a ser analisado
     * @return uma String que indica a validade do documento. Contém tags HTML por ser
     * usada no contexto web
     */
    protected String signatureValidityText(Report report) {
        List<SignatureReport> signatures = report.getSignatures();
        String valid = "<b><u>aprovado</u></b>, em conformidade com";
        boolean hasPA = false;

        if (!signatures.isEmpty()) {
            for (SignatureReport signature: signatures) {
                hasPA |= (signature.getSignaturePolicy() != null);
            }
            SignatureReport.SignatureValidity validity = signatureValidity(signatures);
            if (validity == SignatureReport.SignatureValidity.Valid) {
                if (hasPA) {
                    //! CAdES, XAdES, PAdES
                    return valid + " o padrão ICP-Brasil (DOC-ICP-15)";
                } else if (report.getPaList().isEmpty()) {
                    //! CMS, PDF
                    return valid + " a MP 2.200-2/2001";
                }
            } else if (validity == SignatureReport.SignatureValidity.Indeterminate) {
                return "com validade <b><u>indeterminada</u></b>";
            }
        }

        return "<b><u>reprovado</u></b>";
    }

    /**
     * Mapeia os nomes dos arquivos de assinatura com os respectivos arquivos recebidos
     * através do parâmetro 'signature_file' ou 'signature_files[]' em uma requisição.
     * @param parts as partes de uma requisição HTTP
     * @return um mapa entre nome de arquivos e o conteúdo dos mesmos
     * @throws IOException exceção em caso de erro nos bytes do arquivo
     */
    HashMap<String, byte[]> extractSignatures(Collection<Part> parts) throws IOException {
        HashMap<String, byte[]> result = new HashMap<>();
        ArrayList<Part> partList = new ArrayList<>(parts);
        final String hDisp = "Content-Disposition";

        for (Part p : partList) {
            Collection<String> headers = p.getHeaderNames();
            if (headers.contains(hDisp) || headers.contains(hDisp.toLowerCase())) {
                String[] disp = p.getHeader(hDisp).split("\"");
                boolean validParamName = disp[1].equals("signature_file") || disp[1].equals("signature_files[]");
                /* header must identify that it is a signature with a valid name */
                if (disp.length > 3 && validParamName && disp[2].contains("filename")) {
                    try (InputStream is = p.getInputStream()) {
                        result.put(disp[3], IOUtils.toByteArray(is));
                    }
                }
            }
        }

        return result;
    }

    /**
     * Atribue as configurações de âncoras de confiança ao componente TrustAnchorComponent
     * @param directory o diretório onde serão lidas e salvas as âncoras de confiança
     * @param urls os endereços de onde serão obtidas as âncoras online
     */
    protected void configTrustAnchorComponent(String directory, String urls) {
        AbstractComponentConfiguration.getInstance().component(TrustAnchorComponent.class)
                .paramAppend("trustAnchorsDirectory", directory)
                .paramAppend("trustAnchorsURLs", urls);
    }
}
