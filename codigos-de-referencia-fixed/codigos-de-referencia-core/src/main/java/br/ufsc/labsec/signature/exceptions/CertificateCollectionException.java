package br.ufsc.labsec.signature.exceptions;

public class CertificateCollectionException extends Throwable {
    /*
     * Representa erros na adquirição de certificados por meio de coleções de certificados.
     */
    public static final String CERTIFICATE_NOT_FOUND = "Certificado não encontrado em coleção.";

    public CertificateCollectionException(String message) {
        super(message);
    }

    public CertificateCollectionException() {}
}
