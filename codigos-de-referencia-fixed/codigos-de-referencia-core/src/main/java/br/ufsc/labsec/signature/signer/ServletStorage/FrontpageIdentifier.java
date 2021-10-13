package br.ufsc.labsec.signature.signer.ServletStorage;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.signer.FileFormat;
import br.ufsc.labsec.signature.signer.SignerType;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.logging.Level;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.Part;
import org.apache.commons.io.input.NullInputStream;

/**
 * Esta classe seleciona os dados a serem utilizados para assinatura recebidos em uma requisição
 */
public class FrontpageIdentifier implements SignerRequestInformation {

    /**
     * Requisição HTTP recebida pelo Assinador
     */
    private final HttpServletRequest request;
    /**
     * Mapa que relaciona identificadores dos parâmetros com seu conteúdo
     */
    private final HashMap<String, String> userStringFields = new HashMap<>();
    /**
     * Mapa que relaciona identificadores das partes da requisição com seu conteúdo
     */
    private final HashMap<String, Part> userPartFields = new HashMap<>();

    /**
     * Construtor
     * @param request Requisição HTTP recebida
     */
    public FrontpageIdentifier(HttpServletRequest request) {
        this.request = request;
    }

    /**
     * Adiciona uma parte da requisição ao mapa
     * @param id O identificador da parte
     */
    public void addPartField(String id) {
        try {
            this.userPartFields.put(id, this.request.getPart(id));
        } catch (IOException | ServletException e) {
            Application.logger.log(Level.SEVERE, e.getMessage(), e);
        }
    }

    /**
     * Adiciona um parâmetro da requisição ao mapa
     * @param id O identificador do parâmetro
     */
    public void addStringField(String id) {
        this.userStringFields.put(id, this.request.getParameter(id));
    }

    /**
     * Retorna o mapa de parâmetros
     * @return O mapa de parâmetros
     */
    public HashMap<String, String> getUserStringFields() {
        return this.userStringFields;
    }

    /**
     * Retorna o mapa de partes da requisição
     * @return O mapa de partes
     */
    public HashMap<String, Part> getUserPartFields() {
        return this.userPartFields;
    }

    /**
     * Preenche os mapas com as informações necessárias para que a assinatura seja realizada
     */
    public void fillFields() {
        this.addPartField("signer_certificate");
        this.addStringField("xml_url");
        this.addPartField("file_tbs");
        this.addStringField("password");
        this.addStringField("sig_pol_servlet");
        this.addStringField("sig_format_servlet");
        this.addStringField("suite_sel");
    }

    /**
     * Retorna o certificado do assinante
     * @return O certificado do assinante
     * @throws IOException Exceção em caso de erro na busca pelo certificado
     */
    public InputStream getSignerCertificate() throws IOException {
        return this.userPartFields.get("signer_certificate").getInputStream();
    }

    /**
     * Retorna o arquivo a ser assinado
     * @return O arquivo a ser assinado
     * @throws IOException Exceção em caso de erro na busca pelo arquivo
     */
    @Override
    public InputStream getFileToBeSigned() throws IOException {
        if (this.getFilePart() != null) {
            return this.getFilePart().getInputStream();
        }
        return new NullInputStream(0);
    }

    /**
     * Retorna a parte da requisição com o arquivo a ser assinado
     * @return A parte da requisição com o arquivo a ser assinado
     * @throws IOException Exceção em caso de erro na busca pelo arquivo
     */
    public Part getFilePart() throws IOException {
        return this.userPartFields.get("file_tbs");
    }

    /**
     * Retorna a URL a ser assinada em assinaturas XML/XAdES destacadas
     * @return A URL a ser assinada
     */
    @Override
    public String getXmlUrl() {
        return this.userStringFields.get("xml_url");
    }

    /**
     * Retorna a senha do certificado do assinante
     * @return A senha do certificado
     */
    @Override
    public String getCertificatePassword() {
        return this.userStringFields.get("password");
    }

    /**
     * Retorna a política de assinatura a ser utilizada
     * @return A política de assinatura
     */
    @Override
    public SignerType getSignaturePolicy() {
        return SignerType.fromString(this.userStringFields.get("sig_pol_servlet"));
    }

    /**
     * Retorna o modo de assinatura
     * @return O modo de assinatura
     */
    @Override
    public FileFormat getSignatureFormat() {
        return FileFormat.valueOf(this.userStringFields.get("sig_format_servlet"));
    }

    /**
     * Retorna o algoritmo de assinatura a ser utilizado
     * @return O algoritmo de assinatura
     */
    @Override
    public String getSignatureSuite() {
        return this.userStringFields.get("suite_sel");
    }

    @Override
    public String getPdfReason() {
        return request.getParameter("pdf_reason");
    }

    @Override
    public String getPdfLocation () {
        return request.getParameter("pdf_city") +
                request.getParameter("pdf_state") +
                request.getParameter("pdf_cep");
    }

    /**
     * Retorna o nome do arquivo a ser assinado
     * @return O nome do arquivo a ser assinado
     */
    @Override
    public String getFilename() {
        String filename = null;
        try {
            String fileFormat = ServletUtilities.fileExtension(getSignaturePolicy());
            filename =  ServletUtilities.getFileName(this.getFilePart()) + fileFormat;
        } catch (IOException e) {
            Application.logger.log(Level.SEVERE,
                    "Não foi possível recuperar na requisição o nome do arquivo a ser assinado", e);
        }
        if (filename == null) {
            filename = "";
        }
        return filename;
    }
}
