/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions;

import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe representa uma exceção causada por algum erro
 * no atributo CertValues
 */
public class CertValuesException extends SignatureAttributeException {

    private static final long serialVersionUID = 1L;
    public static final String INVALID_CERTIFICATE = "O seguinte certificado no atributo IdAaEtsCertificateRefs não existe no atributo IdAaEtsCertValues: ";
    public static final String DUPLICATED_ATTRIBUTE = "Existe mais de uma instância do atributo IdAaEtsCertValues na assinatura, porém, somente uma instância do atributo pode ser adicionada.";
    public static final String CERTIFICATE_REFS_NOT_FOUND = "O atributo IdAaEtsCertificateRefs não foi adicionado à assinatura ainda.";
    public static final String NULL_SIGNER_CERTIFICATE = "O certificado do assinante passado no construtor está nulo.";
    public static final String MISSING_OCSP_RESPONSE = "";
    public static final String MISSING_CRL_CERTIFICATE = "";

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public CertValuesException(String message) {
        super(message);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param stackTrace O stack trace da exceção que ocorreu
     */
    public CertValuesException(String message, StackTraceElement[] stackTrace) {
        super(message);
        this.setStackTrace(stackTrace);
    }

    /**
     * Construtor
     * @param invalidCertificate A mensagem de erro
     * @param name Nome do proprietário do certificado
     */
    public CertValuesException(String invalidCertificate, String name) {
        super(invalidCertificate + name);
    }
}
