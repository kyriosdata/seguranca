package br.ufsc.labsec.signature.conformanceVerifier;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.component.Component;
import br.ufsc.labsec.signature.Constants;
import br.ufsc.labsec.signature.Verifier;
import br.ufsc.labsec.signature.conformanceVerifier.cms.exceptions.SignatureNotICPBrException;
import br.ufsc.labsec.signature.conformanceVerifier.gui.ReportGuiComponent;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.MultipartConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.Part;
import org.apache.commons.io.input.NullInputStream;
import org.json.JSONObject;
import java.io.*;
import java.util.*;

/**
 * Servlet que lida com os requests da página inicial.
 *
 * Exemplos usando a ferramenta CURL:
 *      (apenas assinaturas anexadas)
 *          {@code curl -L -v -F "signature_files[]=@<sig.pdf>" -F "signature_files[]=@<sig.p7s>" <URL>}
 *      (apenas assinaturas destacadas)
 *          {@code curl -L -v -F "signature_files[]=@<sig.p7s>" -F "detached_files[]=@<det_sig.dat>" <URL>}
 *
 * A resposta será um JSON com os seguintes campos: "notICPBrSig", "isValidSignature" e "isDetached" que,
 * respectivamente, indicam se o caminho de certificação do certificado do assinante é de uma cadeia
 * aceita pelo Verificador, se o arquivo é um arquivo assinado e se a assinatura é destacada.
 *
 * O recomendado é que a aplicação do Verificador tenha disponível pelo menos 1GB de memória RAM
 * inteiramente para si para que sua execução ocorra sem erros de falta de memória, considerando
 * um grande volume de requisições, sendo em parte requisições simultâneas.
 */
@MultipartConfig
public class IndexServlet extends ReportServlet {

    private static final long serialVersionUID = 4026367963441454183L;

    /*
     * Singleton hack to pass the signature bytes to CompleteServlet. Another
     * workaround, perhaps more elegant, is based on saving the data locally
     * with JavaScript.
     */
    /**
     * Singleton
     */
    private static IndexServlet instance;
    /**
     * Número máximo de arquivos de assinatura por verificação
     */
    private static final int SIG_LIMIT = 4;

    static {
        new ConformanceVerifier();
    }

    /*
     * Tomcat does not work when this constructor is private.
     */

    /**
     * Construtor
     */
    public IndexServlet() {
        super();
        instance = this;
    }

    /**
     * Retorna a instância do Singleton
     * @return a instância de IndexServlet
     */
    static IndexServlet getInstance() {
        if (instance == null) {
            /* never called */
            instance = new IndexServlet();
        }
        return instance;
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
     * Lida com os requests do tipo GET carregando a página inicial do Verificador
     * @param req representa a requisição HTTP
     * @param resp representa a resposta HTTP
     * @throws ServletException exceção em caso de erro no RequestDispatcher da requisição
     * @throws IOException exceção em caso de erro no RequestDispatcher da requisição
     */
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        HttpSession session = req.getSession();
        Enumeration<String> enumeration = session.getAttributeNames();
        while (enumeration.hasMoreElements()) {
            String id = enumeration.nextElement();
            session.removeAttribute(id);
        }

        resp.setHeader("Cache-Control",
                "no-cache, no-store, must-revalidate"); // HTTP 1.1.
        resp.setHeader("Pragma", "no-cache"); // HTTP 1.0.
        resp.setDateHeader("Expires", 0);

        req.setAttribute("version", this.getVersion());
        req.getRequestDispatcher("index.jsp").forward(req, resp);
    }

    /**
     * Lida com os requests do tipo POST realizando algumas verificações nos arquivos enviados
     * @param req representa a requisição HTTP
     * @param resp representa a resposta HTTP
     * @throws ServletException exceção em caso de erro no retorno das partes da requisição
     * @throws IOException exceção em caso de erro na extração dos arquivos de assinatura
     * das partes da requisição
     */
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        if (req.getContentType() == null) {
            // empty POST on curl
            return;
        }

        Collection<Part> parts = req.getParts();

        HashMap<String, byte[]> sigsFromRequest = super.extractSignatures(parts);

        if (sigsFromRequest.size() > SIG_LIMIT) {
            resp.getWriter().write("{\"limit\":" + SIG_LIMIT + "}");
            return;
        }

        HashMap<String, HashMap<String, Boolean>> result = new HashMap<>();
        for (Map.Entry<String, byte[]> entry : sigsFromRequest.entrySet()) {
            result.put(entry.getKey(), signatureValues(entry.getKey(), entry.getValue()));
        }

        resp.setCharacterEncoding(UTF8_CHARSET.name());
        resp.setContentType("application/json");
        resp.getWriter().write(String.valueOf(new JSONObject(result)));
    }

    /**
     * Realiza uma análise inicial do arquivo de assinatura, verificando se o certificado
     * do assinante possui um caminho de certificação aceito, se o arquivo é um arquivo de
     * assinatura e se a assinatura é destacada.
     * @param filename nome do arquivo a ser verificado
     * @param signature os bytes do arquivo
     * @return mapa que relaciona os itens verificados com os seus valores
     */
    private HashMap<String, Boolean> signatureValues(String filename, byte[] signature) {
        if (signature.length == 0) {
            /*
             * Could happen if some user "accidentally" removes the
             * "required" field from the HTML source.
             */
            return null;
        }

        Application app = new Application(
                new ByteArrayInputStream(signature),
                new NullInputStream(0),
                filename);
        app.setup();

        Component rgc = app.getComponent(ReportGuiComponent.class.getName());
        Verifier v = null;
        HashMap<String, Boolean> sigValues = new HashMap<>();
        try {
            v = ((ReportGuiComponent) rgc).chooseSignatureVerifier();
        } catch (SignatureNotICPBrException e) {
            sigValues.put("notICPBrSig", true);
        }

        sigValues.put("isValidSignature", v != null);
        sigValues.put("isDetached", v != null && v.needSignedContent());

        return sigValues;
    }

    /**
     * Retorna a versão do Verificador de Conformidade
     * @return a versão atual do sistema
     */
    private String getVersion() {
        String version = Constants.SOFTWARE_VERSION;
        InputStream is = this.getClass().getClassLoader()
                .getResourceAsStream("git.properties");

        if (is == null) {
            /*
             * Classes have not been compiled manually and therefore the
             * desired file does not exist. Return the known constant.
             */
            return version;
        }

        try (BufferedReader br = new BufferedReader(new InputStreamReader(is))) {
            String line;
            /* matches the first JSON line with the string "describe" */
            while ((line = br.readLine()) != null && !line.contains("describe")) {
            }
            if (line != null) {
                version = line.split("\"")[3];
            }
        } catch (IOException ignored) {
        }

        return version;
    }

}
