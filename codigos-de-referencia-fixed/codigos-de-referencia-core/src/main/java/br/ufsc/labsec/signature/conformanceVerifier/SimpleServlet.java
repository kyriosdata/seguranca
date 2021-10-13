package br.ufsc.labsec.signature.conformanceVerifier;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.component.Component;
import br.ufsc.labsec.signature.SignatureDataWrapper;
import br.ufsc.labsec.signature.conformanceVerifier.gui.ReportGuiComponent;
import br.ufsc.labsec.signature.conformanceVerifier.report.Report;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.MultipartConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Part;
import org.apache.fop.apps.FOPException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

/**
 * O ReportServlet que lida com as requisições HTTP (POSTs) enviadas por linha de comando.
 * Exemplos usando a ferramenta CURL:
 *      (apenas assinaturas anexadas)
 *          {@code curl -L -v -F "signature_files[]=@<sig.pdf>" -F "signature_files[]=@<sig.p7s>" <URL>}
 *      (apenas assinaturas destacadas)
 *          {@code curl -L -v -F "signature_files[]=@<sig.p7s>" -F "detached_files[]=@<det_sig.dat>" <URL>}
 *
 * No primeiro caso há duas assinaturas anexadas a serem verificadas.
 * No segundo caso há uma única assinatura a ser verificada, com o seu arquivo destacado como segundo parâmetro.
 * Como no primeiro caso, mais de uma assinatura pode ser enviada no mesmo request com seu arquivo destacado.
 *
 * Assinaturas anexadas e destacadas no mesmo request não são permitidas.
 *
 *
 * É possivel restringir o acesso a este servlet através do IP que o está acessando.
 * Em <code>$CATALINA_BASE/webapps/verifier-{version}/WEB-INF/web.xml</code>, é possível adicionar o filtro
 *
 * {@code
 * <filter>
 *     <filter-name>Remote Address Filter</filter-name>
 *     <filter-class>org.apache.catalina.filters.RemoteAddrFilter</filter-class>
 *     <init-param>
 *         <param-name>allow</param-name>
 *         <param-value>
 *             150\.162\.66\.\d+|150\.162\.56\.\d+|
 *             127\.\d+\.\d+\.\d+|::1|0:0:0:0:0:0:0:1
 *         </param-value>
 *     </init-param>
 * </filter>
 * <filter-mapping>
 *     <filter-name>Remote Address Filter</filter-name>
 *     <url-pattern>/report</url-pattern>
 * </filter-mapping>
 * }
 * Os IPs adicionados no paramêtro serão os únicos com permissão de acesso à API <code>/report</code>.
 * No exemplo, são aceitas as faixas 150.162.66 e 150.162.56 e a segunda linha indica o aceite do localhost.
 * Cada opção é separada por |.
 */
@MultipartConfig
public class SimpleServlet extends ReportServlet {

    private static final long serialVersionUID = 3658945130626333321L;
    /**
     * Tipo do relatório (JSON ou XML)
     */
    private String reportType;

    static {
        new ConformanceVerifier();
    }

    /**
     * Inicialização do Servlet
     */
    @Override
    public void init() {
        this.configTrustAnchorComponent(this.getServletContext().getInitParameter("trustAnchorsDirectory"),
                this.getServletContext().getInitParameter("trustAnchorsURLs"));
    }

    /**
     * Lida com os requests do tipo POST realizando a verificação das assinaturas
     * dos arquivos e retornando o relatório no tipo especificado
     * @param request representa a requisição HTTP
     * @param response representa a resposta HTTP
     * @throws ServletException exceção em caso de erro no retorno das partes da requisição
     * @throws IOException exceção em caso de erro na extração dos arquivos de assinatura
     * das partes da requisição
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        List<SignatureDataWrapper> dataWrappersList = this.createSignatureDataWrappers(request);
        Application app = new Application(dataWrappersList);
        app.setup();

        Component rgc = app.getComponent(ReportGuiComponent.class.getName());
        List<Report> reportList = ((ReportGuiComponent) rgc).startVerification();
        for (int i=0; i<reportList.size(); ++i) { reportList.get(i).setNumber(i+1); }

        reportType = request.getParameter("report_type");
        if (reportType == null) {
            reportType = "json";
        }

        response.setCharacterEncoding(UTF8_CHARSET.name());

        if (reportType.toLowerCase().equals("xml")) {
            response.setContentType("text/xml");
            try {
                String reportString = generateXmlReportsString(reportList);
                response.getWriter().write(reportString);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else if (reportType.toLowerCase().equals("pdf")) {
            try {
                generatePDFReports(app, reportList, response, request);
            } catch (TransformerException e) {
                e.printStackTrace();
            } catch (FOPException e) {
                e.printStackTrace();
            }
        } else if (reportType.toLowerCase().equals("json"))  {
            response.setContentType("application/json");
            response.getWriter().write(this.generateJsonReportsString(reportList));
        } else {
            response.setContentType("text/html");
            response.getWriter().write("\nPor favor, insira um report_type válido (JSON ou XML)\n\n");
        }
    }

    /**
     * Cria uma lista de {@see SignatureDataWrappers} que corresponde às assinaturas a serem
     * verificadas. A lista pode ser gerada de duas formas: apenas assinaturas anexadas ou
     * apenas assinaturas destacadas.
     * @param request representa a requisição HTTP
     * @return a lista de {@see SignatureDataWrappers} com as assinaturas a serem verificadas
     * @throws IOException exceção em caso de erro na extração dos arquivos de assinatura
     * das partes da requisição
     * @throws ServletException exceção em caso de erro no retorno das partes da requisição
     */
    private List<SignatureDataWrapper> createSignatureDataWrappers(HttpServletRequest request) throws IOException,
            ServletException {
        if (this.hasDetachedFiles(request.getParts().toArray())) {
            return createSignatureDataWrappersDetached(request);
        } else {
            return createSignatureDataWrappersAttached(request);
        }
    }

    /**
     * Cria uma lista de {@see SignatureDataWrappers} com apenas assinaturas anexadas.
     * @param request representa a requisição HTTP
     * @return a lista de {@see SignatureDataWrappers} com as assinaturas a serem verificadas
     * @throws IOException exceção em caso de erro na extração dos arquivos de assinatura
     * das partes da requisição
     * @throws ServletException exceção em caso de erro no retorno das partes da requisição
     */
    private List<SignatureDataWrapper> createSignatureDataWrappersAttached(HttpServletRequest request)
            throws IOException, ServletException {
        List<SignatureDataWrapper> wrappers = new ArrayList<>();
        Object[] parts = request.getParts().toArray();
        for (Object part : parts) {
            Part p = (Part) part;
            String header = p.getHeader("content-disposition");
            if (header.contains("signature_files[]")) {
                InputStream sigStream = p.getInputStream();
                String filename = "";
                if (header.contains("filename")) {
                    int pos = header.indexOf("filename");
                    filename = header.substring(pos+10, header.length()-1);
                }
                wrappers.add(new SignatureDataWrapper(sigStream, null, filename));
            }
        }
        return wrappers;
    }

    /**
     * Cria uma lista de {@see SignatureDataWrappers} com apenas assinaturas destacadas.
     * @param request representa a requisição HTTP
     * @return a lista de {@see SignatureDataWrappers} com as assinaturas a serem verificadas
     * @throws IOException exceção em caso de erro na extração dos arquivos de assinatura
     * das partes da requisição
     * @throws ServletException exceção em caso de erro no retorno das partes da requisição
     */
    private List<SignatureDataWrapper> createSignatureDataWrappersDetached(HttpServletRequest request)
            throws IOException, ServletException {
        List<SignatureDataWrapper> wrappers = new ArrayList<>();
        Object[] parts = request.getParts().toArray();
        for (int i = 0; i < parts.length/2+1; ++i) {
            Part p = (Part) parts[i];
            String header = p.getHeader("content-disposition");
            if (header.contains("signature_files[]")) {
                InputStream sigStream = p.getInputStream();
                String filename = "";
                if (header.contains("filename")) {
                    int pos = header.indexOf("filename");
                    filename = header.substring(pos+10, header.length()-1);
                }
                InputStream detStream = correspondingDetached(parts, i);
                wrappers.add(new SignatureDataWrapper(sigStream, detStream, filename));
            }
        }
        return wrappers;
    }

    /**
     * Retorna o InputStream das partes da requisição correspondente à parts[i]. Isto é, a parte dos arquivos
     * destacados que corresponde ao arquivo de assinatura contido em parts[i].
     * @param parts as partes de uma requisição HTTP
     * @param i o índice nas partes da requisição que corresponde ao arquivo de assinatura
     * @return o InputStream de um arquivo destacado, o qual corresponde ao arquivo de assinatura parts[i]
     */
    private InputStream correspondingDetached(Object[] parts, int i) {
        int lastSig = (int) Math.ceil(parts.length/2);
        Part detPart = (Part) parts[lastSig];
        try {
            return detPart.getInputStream();
        } catch (IOException e) {
            Application.logger.log(Level.SEVERE,
                    "Não foi possível obter o InputStream do arquivo detached da assinatura " + (i+1) + ".", e);
            return null;
        }
    }

    /**
     * Gera uma String que contém um array de JSONs que correspondem a cada relatório na lista dada
     * @param reportList lista de objetos Report que serão transformados em strings no formato JSON
     * @return uma String que representa todos os relatórios de verificação, cada um em formato JSON.
     * É a resposta de uma requisição à esse Servlet
     *
     * @see super.reportToJsonString()
     */
    private String generateJsonReportsString(List<Report> reportList) {
        StringBuilder jsonStrBuilder = new StringBuilder();
        Report r1 = reportList.get(0);
        jsonStrBuilder.append(super.reportToJsonString(r1));
        int keyLenght = "{\"report\":".length();
        if (reportList.size() > 1) {
            // transforms the key "report" to an array
            jsonStrBuilder.replace(keyLenght+1, keyLenght+3, "[ {"); // substitutes "{" for "[", that represents an array
            jsonStrBuilder.setLength(jsonStrBuilder.length()-1); // removes last "}"
        }
        for (int i = 1; i < reportList.size(); ++i) {
            String jsonReportStr = super.reportToJsonString(reportList.get(i));
            jsonReportStr = jsonReportStr.substring(keyLenght); // removes the report key in the object, that is " {"report": "
            jsonReportStr = jsonReportStr.substring(0, jsonReportStr.length()-1); // removes last "}"
            jsonStrBuilder.append(", ").append(jsonReportStr);
        }
        if (reportList.size() > 1) {
            jsonStrBuilder.append("]}");
        }
        return jsonStrBuilder.toString();
    }

    /**
     * Gera uma String que contém cada relatório da lista em formato XML
     * @param reportList lista de objetos Report que serão transformados em strings no formato XML
     * @return ma String que representa todos os relatórios de verificação, cada um em formato XML
     * É a resposta de uma requisição à esse Servlet
     */
    private String generateXmlReportsString(List<Report> reportList) {
        try {
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
            Document result = documentBuilder.newDocument();

            Element root = result.createElement("reports");

            for (Report r : reportList) {
                Document reportDocument = r.generate();
                XPathFactory xPathFactory = XPathFactory.newInstance();
                XPath xpath = xPathFactory.newXPath();

                XPathExpression exprAssertion = xpath.compile("/*");
                Element assertionNode = (Element) exprAssertion.evaluate(reportDocument, XPathConstants.NODE);
                Node importedNode = reportDocument.importNode(assertionNode, true);
                result.adoptNode(importedNode);
                root.appendChild(importedNode);
            }

            result.appendChild(root);

            return docToString(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Verifica se há algum arquivo destacado entre as partes
     * @param parts array das partes do request HTTP
     * @return indica se há algum arquivo destacado
     */
    private boolean hasDetachedFiles(Object[] parts) {
        for (Object obj : parts) {
            if (((Part) obj).getName().equals("detached_files[]")) return true;
        }
        return false;
    }

}
