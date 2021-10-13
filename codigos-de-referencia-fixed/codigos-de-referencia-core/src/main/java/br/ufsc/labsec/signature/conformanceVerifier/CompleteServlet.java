package br.ufsc.labsec.signature.conformanceVerifier;

import br.ufsc.labsec.component.Component;
import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.SignatureDataWrapper;
import br.ufsc.labsec.signature.conformanceVerifier.report.Report;
import br.ufsc.labsec.signature.exceptions.NullSignatureFileNameException;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.gui.ReportGuiComponent;
import br.ufsc.labsec.signature.exceptions.EmptySignatureReportListException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignatureComponent;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.MultipartConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.Part;
import org.bouncycastle.util.io.Streams;
import org.apache.fop.apps.FOPException;
import org.apache.commons.io.input.NullInputStream;


import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.Level;


/**
 * O ReportServlet que lida com as requisições HTTP (POSTs) enviadas por um browser (Verificador Web).
 *
 * É possível restringir a quantidade máxima de request a este servlet criando o arquivo
 * <code>$CATALINA_BASE/webapps/verifier-{version}/META-INF/context.xml</code> com o seguinte conteúdo
 *
 * {@code
 * < ?xml version="1.0" encoding="UTF-8"?>
 * <Context path="/webreport">
 * 	<Valve className="org.apache.catalina.valves.SemaphoreValve"
 * 	           concurrency="150" block="false" fairness="false" />
 * </Context>
 * }
 *
 * onde o valor de <code>concurrency</code> indica a quantidade máxima de requests concorrentes permitidos.
 */
@MultipartConfig
public class CompleteServlet extends ReportServlet {

    private static final long serialVersionUID = 3658945130626333321L;

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
	 * dos arquivos e retornando o relatório em HTML
	 * @param request representa a requisição HTTP
	 * @param response representa a resposta HTTP
	 * @throws ServletException exceção em caso de erro no retorno das partes da requisição
	 * @throws IOException exceção em caso de erro na extração dos arquivos de assinatura
	 * das partes da requisição
	 */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        request.setCharacterEncoding(UTF8_CHARSET.name());
        HttpSession session = request.getSession();

        Report.ReportType type = Report.ReportType.HTML;
        if (request.getPart("report_type") != null) {
            //! Translate the report type obtained as a Part from 'request' to the enum ReportType.
            byte[] typePartStream = Streams.readAll(request.getPart("report_type").getInputStream());
            type = Report.ReportType.valueOf(new String(typePartStream, UTF8_CHARSET).toUpperCase());
        }

        //!< HashMap that provides the bytes of signatures to be verified.
        Map<String, byte[]> signaturesMap = super.extractSignatures(request.getParts());
        session.setAttribute("numOfSignatures", signaturesMap.size());

        String signature_text = request.getParameter("signature_text_box0");
        if (signature_text != null && signature_text.equals("")) {
            //! Unexpected use of POST (the request was sent without selecting a signature file).
            response.sendRedirect(request.getContextPath());
            return;
        }

        List<SignatureDataWrapper> streamPairs = new ArrayList<>();  //!< data do be verified.
        Object[] parts = request.getParts().toArray();
        for (int i = 0; i < signaturesMap.size(); ++i) {
            //!< The name of the i-th signature file selected in the web page.
            String sigFileName = request.getParameter("signature_text_box" + i);
            InputStream sigStream = new ByteArrayInputStream(signaturesMap.get(sigFileName));
            InputStream detStream = new NullInputStream(0);
            Part detachedPart = this.findDetachedPart("detached_file" + i, parts);
            if (detachedPart != null) {
                //! sigFileName in a detached signature.
                detStream = detachedPart.getInputStream();
            }
            streamPairs.add(new SignatureDataWrapper(sigStream, detStream, sigFileName));
        }

        Application app = new Application(streamPairs);
        app.setup();

        Component rgc = app.getComponent(ReportGuiComponent.class.getName());
        List<Report> reportList = ((ReportGuiComponent) rgc).startVerification();
        if (type == Report.ReportType.PDF) {
            try {
                String sigFileName;

                if (request.getParameter("signature_text_box1") == null) {
                    sigFileName = request.getParameter("signature_text_box0") + "-verificado.pdf";
                } else {
                    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd");
                    sigFileName = "relatorio-verificador-" + dateFormat.format(new Date()) + ".pdf";
                }

                response.setHeader("Content-Disposition", String.format("attachment; filename=%s", sigFileName));
                super.generatePDFReports(app, reportList, response, request);
                return;
            } catch(FOPException e) {
                Application.logger.log(Level.SEVERE, "Erro na trasformação do arquivo de configuração.", e);
            } catch (TransformerException e) {
                Application.logger.log(Level.SEVERE, "Erro no arquivo de configuração do relatório.", e);
            }
        } else {
            try {  //!< TODO revisar os tratamentos de exceção que alteram o estado de response.
                this.generateHTMLReports(app, reportList, request);
                request.getRequestDispatcher("report.jsp").forward(request, response);
                return;
            } catch (NullSignatureFileNameException e) {
                Report r = e.getSignatureReport();
                response.setCharacterEncoding(UTF8_CHARSET.name());
                response.setContentType("application/json");
                response.getWriter().write(super.reportToJsonString(r));
                return;
            } catch (EmptySignatureReportListException e) {
                response.sendRedirect(request.getContextPath());
                return;
            } catch (TransformerConfigurationException e) {
                Application.logger.log(Level.SEVERE, "Erro no arquivo de configuração do relatório.", e);
                return;
            }
        }

        request.getRequestDispatcher("report.jsp").forward(request, response);
    }

	/**
	 * Preenche a sessão da requisição HTTP dada com os atributos de cada relatório na lista
	 * @param app a aplicação do Verificador de Conformidade
	 * @param reportList a lista de relatórios de verificação
	 * @param request representa a requisição HTTP
	 * @throws TransformerConfigurationException exceção em caso de erro na criação da instância
	 * do Transformer
	 * @throws NullSignatureFileNameException exceção em caso de nome nulo no arquivo de assinatura
	 * @throws EmptySignatureReportListException exceção em caso de relatório sem nenhuma assinatura
	 */
    private void generateHTMLReports(Application app, List<Report> reportList, HttpServletRequest request)
            throws TransformerConfigurationException, NullSignatureFileNameException, EmptySignatureReportListException {
        Component csc = app.getComponent(CadesSignatureComponent.class.getName());
        String xslPath = app.getComponentParam(csc, "reportStylePathHTML");
        Source xslt = new StreamSource(Application.class.getResourceAsStream("/" + xslPath));
        Transformer t = TransformerFactory.newInstance().newTransformer(xslt);

        for (int i = 0; i < reportList.size(); ++i) {
            Report r = reportList.get(i);
            String sigFileName = request.getParameter("signature_text_box" + i);

            if (sigFileName == null) {
                throw new NullSignatureFileNameException(r);
            } else if (r.getSignatures().isEmpty()) {
                throw new EmptySignatureReportListException();
            }

            r.setNumber(i+1);

            String snAttr = "subjectName" + i,
                    sigValidityAttr = "signatureValidityAttr" + i,
                    sigValidity = "signatureValidity" + i;
            List<SignatureReport> sigReportList = r.getSignatures();
            if (!sigReportList.isEmpty()) {
                StringBuilder names = new StringBuilder();
                for (SignatureReport sr : sigReportList) {
                    names.append(sr.getSignerSubjectName()).append("<br>");
                }
                request.setAttribute(snAttr, names.toString());
            } else {
                request.setAttribute(snAttr, "Não há assinaturas");
                request.setAttribute("signaturePolicy", "");
            }
            request.setAttribute(sigValidityAttr, signatureValidityText(r));
            request.setAttribute(sigValidity, signatureValidity(r.getSignatures()).name().toLowerCase());


            ByteArrayOutputStream os = new ByteArrayOutputStream();
            DOMSource d = new DOMSource(r.generate());
            try {
                t.transform(d, new StreamResult(os));
            } catch (TransformerException e) {
                Application.logger.log(
                        Level.SEVERE, "Não foi possível fazer a transformação do relatório em formato DOM.", e);
            }

            String reportAttr = "report" + i;
            request.setAttribute(reportAttr, new String(os.toByteArray(), UTF8_CHARSET));

            HttpSession s = request.getSession();
            s.setAttribute(reportAttr, request.getAttribute(reportAttr));
            s.setAttribute(snAttr, request.getAttribute(snAttr));
            s.setAttribute(sigValidityAttr, request.getAttribute(sigValidityAttr));
            s.setAttribute(sigValidity, request.getAttribute(sigValidity));
        }
    }

	/**
	 * Encontra o objeto Part com o nome dado
	 * @param name o nome da Part desejada
	 * @param parts as partes de uma requisição HTTP
	 * @return a parte desejada, ou null se não for encontrada
	 */
    private Part findDetachedPart(String name, Object[] parts) {
        for (Object part : parts) {
            if (((Part) part).getName().equals(name))
                return (Part) part;
        }
        return null;
    }

}
