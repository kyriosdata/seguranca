package br.ufsc.labsec.signature.signer.ServletStorage;

import br.ufsc.labsec.signature.signer.FileFormat;
import br.ufsc.labsec.signature.signer.SignerType;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;

/**
 * Esta classe reune os dados a serem utilizados para assinatura. Utilizada para auxiliar nos testes do Assinador
 */
public class CommonSignerRequestInformation implements SignerRequestInformation {

    public final String CERTIFICATE_PASSWORD = "certificate_password";
    public final String FILE_TO_BE_SIGNED = "file_to_be_signed";
    public final String XML_URL = "xml_url";
    public final String SIG_POLICY = "sig_policy";
    public final String SIG_FORMAT = "sig_format";
    public final String SIG_SUITE = "sig_suite";
    public final String PDF_LOCATION = "pdf_location";
    public final String PDF_REASON = "pdf_reason";
    public final String FILENAME = "filename";

    /**
     * Mapa que relaciona identificadores dos parâmetros com seu conteúdo
     */
    HashMap<String, Object> store;

    /**
     * Construtor
     */
    public CommonSignerRequestInformation() {
        store = new HashMap<>();
    }

    /**
     * Atribue o arquivo a ser assinado
     * @param file O arquivo a ser assinado
     */
    public void setFileToBeSigned(InputStream file) {
        store.put(FILE_TO_BE_SIGNED, file);
    }

    /**
     * Atribue a senha do certificado do assinante
     * @param password A senha do certificado do assinante
     */
    public void setCertificatePassword(String password) {
        store.put(CERTIFICATE_PASSWORD, password);
    }

    /**
     * Atribue a URL do arquivo a ser assinado
     * @param url A URL do arquivo a ser assinado
     */
    public void setXmlUrl(String url) {
        store.put(XML_URL, url);
    }

    /**
     * Atribue a política de assinatura a ser utilizada
     * @param policy A política de assinatura
     */
    public void setSignaturePolicy(SignerType policy) {
        store.put(SIG_POLICY, policy);
    }

    /**
     * Atribue o modo de assinatura
     * @param format O modo de assinatura
     */
    public void setSignatureFormat(FileFormat format) {
        store.put(SIG_FORMAT, format);
    }

    /**
     * Atribue o algoritmo de assinatura a ser utilizado
     * @param suite O algoritmo da assinatura
     */
    public void setSignatureSuite(String suite) {
        store.put(SIG_SUITE, suite);
    }

    public void setPdfReason(String reason) {
        store.put(PDF_REASON, reason);
    }

    public void setPdfLocation(String location) {
        store.put(PDF_LOCATION, location);
    }

    /**
     * Atribue o caminho do arquivo a ser assinado
     * @param filename O caminho do arquivo a ser assinado
     */
    public void setFilename(String filename) {
        store.put(FILENAME, filename);
    }

    /**
     * Retorna o arquivo a ser assinado
     * @return O arquivo a ser assinado
     * @throws IOException Exceção em caso de erro na busca pelo arquivo
     */
    @Override
    public InputStream getFileToBeSigned() throws IOException {
        return (InputStream) store.get(FILE_TO_BE_SIGNED);
    }

    /**
     * Retorna a senha do certificado do assinante
     * @return A senha do certificado
     */
    @Override
    public String getCertificatePassword() {
        return (String) store.get(CERTIFICATE_PASSWORD);
    }

    /**
     * Retorna a URL a ser assinada em assinaturas XML/XAdES destacadas
     * @return A URL a ser assinada
     */
    @Override
    public String getXmlUrl() {
        return (String) store.get(XML_URL);
    }

    /**
     * Retorna a política de assinatura a ser utilizada
     * @return A política de assinatura
     */
    @Override
    public SignerType getSignaturePolicy() {
        return (SignerType) store.get(SIG_POLICY);
    }

    /**
     * Retorna o modo de assinatura
     * @return O modo de assinatura
     */
    @Override
    public FileFormat getSignatureFormat() {
        return (FileFormat) store.get(SIG_FORMAT);
    }

    /**
     * Retorna o algoritmo de assinatura a ser utilizado
     * @return O algoritmo de assinatura
     */
    @Override
    public String getSignatureSuite() {
        return (String) store.get(SIG_SUITE);
    }

    @Override
    public String getPdfReason() {
        return (String) store.get(PDF_REASON);
    }

    @Override
    public String getPdfLocation() {
        return (String) store.get(PDF_LOCATION);
    }

    /**
     * Retorna o nome do arquivo a ser assinado
     * @return O nome do arquivo a ser assinado
     */
    @Override
    public String getFilename() {
        return (String) store.get(FILENAME);
    }
}
