/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions;

import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe representa uma exceção causada por algum erro
 * no atributo CertRefs
 */
public class CertificateRefsException extends SignatureAttributeException {

    private static final long serialVersionUID = 1L;
    public static final String MISSING_CERTIFICATE = "O atributo id-aa-ets-certificateRefs não contém o seguinte certificado presente no caminho de certificação: ";
    public static final String DUPLICATED_ATTRIBUTE = "Existe mais de uma instância do atributo id-aa-ets-certificateRefs na assinatura, porém, somente uma instância do atributo pode ser adicionada.";
    public static final String WRONG_SIZE_OF_CERTIFICATES = "O tamanho da lista de certificados do atributo id-aa-ets-certificateRefs não é o mesmo do caminho de certificação.";

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public CertificateRefsException(String message) {
        super(message);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param stackTrace O stack trace da exceção que ocorreu
     */
    public CertificateRefsException(String message, StackTraceElement[] stackTrace) {
        super(message);
        this.setStackTrace(stackTrace);
    }

    /**
     * Construtor
     * @param invalidCertificate A mensagem de erro
     * @param name Nome do proprietário do certificado
     */
    public CertificateRefsException(String invalidCertificate, String name) {
        super(invalidCertificate + name);
    }
}
