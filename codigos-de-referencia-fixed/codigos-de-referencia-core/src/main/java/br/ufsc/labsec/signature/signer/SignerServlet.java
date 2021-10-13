package br.ufsc.labsec.signature.signer;

import br.ufsc.labsec.component.AbstractComponentConfiguration;
import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.component.Component;
import br.ufsc.labsec.signature.SignatureDataWrapper;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.TrustAnchorComponent;
import br.ufsc.labsec.signature.signer.PolicyStorage.StamperComponent;
import br.ufsc.labsec.signature.signer.ServletStorage.*;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.MultipartConfig;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Part;
import org.apache.commons.io.input.NullInputStream;
import org.apache.pdfbox.io.IOUtils;
import org.json.JSONObject;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.logging.Level;
import java.util.zip.ZipOutputStream;
import java.security.KeyStore;

/**
 * Servlet que lida com os requests da página inicial do assinador.
 */
@MultipartConfig
public class SignerServlet extends HttpServlet {

    protected final Charset UTF8_CHARSET = StandardCharsets.UTF_8;

    static {
        new ReferenceSigner();
    }

    /**
     * Inicialização do Servlet
     */
    @Override
    public void init() {
        this.configTrustAnchorComponent(this.getServletContext().getInitParameter("trustAnchorsDirectory"),
                this.getServletContext().getInitParameter("trustAnchorsURLs"));
        this.configureTimeStampProvider(this.getServletContext().getInitParameter("tsaSSLCertificates"));
    }

    /**
     * Lida com os requests do tipo GET carregando a página inicial do Assinador
     * @param req representa a requisição HTTP
     * @param resp representa a resposta HTTP
     * @throws ServletException exceção em caso de erro no RequestDispatcher da requisição
     * @throws IOException exceção em caso de erro no RequestDispatcher da requisição
     */
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        req.setAttribute("version", ServletUtilities.getVersion());
        InputStream policyInfoStream = this.getClass().getResourceAsStream("/resources/signer-policies-information.json");
        byte[] bytes = IOUtils.toByteArray(policyInfoStream);
        req.setAttribute("policyInfoJson", new String(bytes));
        req.getRequestDispatcher("index.jsp").forward(req, resp);
    }

    /**
     * Lida com os requests do tipo POST realizando a assinatura sobre os arquivos enviados
     * @param req representa a requisição HTTP
     * @param resp representa a resposta HTTP
     * @throws ServletException exceção em caso de erro no retorno das partes da requisição
     * @throws IOException exceção em caso de erro na extração dos arquivos de assinatura
     * das partes da requisição
     */
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        Application app = new Application(new ArrayList<SignatureDataWrapper>());
        app.setup();

        Component sc = app.getComponent(StamperComponent.class.getName());

        FrontpageIdentifier frontpageIdentifier = new FrontpageIdentifier(req);
        frontpageIdentifier.fillFields();

        InputStream p12 = frontpageIdentifier.getSignerCertificate();

        Part fileTbsPart = frontpageIdentifier.getFilePart();
        ServletUtilities.isFieldEmpty(req, resp, fileTbsPart.toString());

        KeyStore ks = ServletUtilities.keyStoreInitializer();
        String passwordString = frontpageIdentifier.getCertificatePassword();

        Map<String, Boolean> error = new HashMap<>();
        List<SignatureDataWrapper> signatureDataWrappers = new ArrayList<>();

        ArrayList<SignatureChain> signatureChainList = new ArrayList<>();
        ServletUtilities.ServletSignatureErrorHandler signatureErrorHandler =
                new ServletUtilities.ServletSignatureErrorHandler();
        ServletUtilities.ServletAlgorithmErrorHandler algorithmErrorHandler =
                new ServletUtilities.ServletAlgorithmErrorHandler();

        try {
            ServletUtilities.loadKeyStore(Objects.requireNonNull(ks), p12, passwordString.toCharArray());

            SignatureChain signatureChain = new SignatureChain(frontpageIdentifier, ks, signatureErrorHandler, algorithmErrorHandler);
            signatureChainList.add(signatureChain);

            ((StamperComponent) sc).startStamp(signatureChainList);

            signatureDataWrappers = app.getSignatureWrapperList();
        } catch (IOException e) {
            Application.logger.log(Level.WARNING, e.getMessage(), e);
            error.put("passwordError", true);
        }

        if (signatureErrorHandler.hasError()) {
            if (signatureErrorHandler.isCertPathError()) {
                error.put("certPathError", true);
            } else if (signatureErrorHandler.isMalformedFileError()) {
                error.put("malformedFile", true);
            } else {
                error.put("signatureError", true);
            }
        } else if (algorithmErrorHandler.hasError()) {
            error.put("algorithmError", true);
        } else if (error.isEmpty() && signatureDataWrappers.size() > 1) {
            ServletUtilities.turnOnPreamble(req, resp);
            ZipOutputStream zipOut = new ZipOutputStream(resp.getOutputStream());
            ServletUtilities.fillZip(zipOut, signatureDataWrappers);
        } else if (error.isEmpty() && signatureDataWrappers.size() == 1) {
            SignatureDataWrapper signatureDataWrapper = signatureDataWrappers.get(0);
            ServletUtilities.turnOnPreamble(req, resp, signatureDataWrapper.name());
            OutputStream out = resp.getOutputStream();
            byte[] signature;
            if (!(signatureDataWrapper.det() instanceof NullInputStream)) {
                signature = IOUtils.toByteArray(signatureDataWrapper.det());
            } else {
                signature = IOUtils.toByteArray(signatureDataWrapper.sig());
            }
            ServletUtilities.writeFile(out, signature);
        }
        if (!error.isEmpty()) {
            resp.setCharacterEncoding(UTF8_CHARSET.name());
            resp.setContentType("application/json");
            resp.getWriter().write(String.valueOf(new JSONObject(error)));
        }
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

    protected void configureTimeStampProvider(String sslCertificateUrls) {
        AbstractComponentConfiguration.getInstance().component(TrustAnchorComponent.class)
                .paramAppend("tsaSSLCertificates", sslCertificateUrls);
    }
}