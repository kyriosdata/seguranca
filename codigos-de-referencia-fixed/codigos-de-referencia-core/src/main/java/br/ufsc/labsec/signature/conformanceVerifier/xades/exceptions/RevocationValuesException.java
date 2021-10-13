/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions;

import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe representa uma exceção causada por algum erro
 * relacionado ao atributo RevocationValues em uma assinatura
 */
public class RevocationValuesException extends SignatureAttributeException {

    private static final long serialVersionUID = 1L;
    public static final String NULL_CRLS_LIST = "A lista de LCRs passada para construir o atributo RevocationValues é nula.";
    public static final String NULL_OCSP_LIST = "A lista de OCSPs passada para construir o atributo RevocationValues é nula.";
    public static final String DUPLICATED_ATTRIBUTE = "Existe mais de uma instância do atributo RevocationValues na assinatura, porém, somente uma instância do atributo pode ser adicionada.";
    public static final String COMPLETE_REVOCATION_REFS_NOT_FOUND = "O atributo CompleteRevocationRefs não foi adicionado à assinatura.";
    public static final String MISSING_ATTRIBUTES = "O atributo CompleteRevocationRefs necessita de pelo menos um atributo para ser construiído, "
            + "porém nenhum atributo foi passado no construtor.";
    public static final String MISSING_OCSP_RESPONSE = "Existe uma resposta OCSP no atributo CompleteRevocationRefs que não está presente no atributo RevocationValues.";
    public static final String MISSING_CRL_CERTIFICATE = "Existe uma CRL no atributo CompleteRevocationRefs que não está presente no atributo RevocationValues.";
    public static final String INVALID_NUMBER_OF_CRLS = "O atributo RevocationValues contém menos CRLs do que o atributo CompleteRevocationRefs.";
    public static final String INVALID_NUMBER_OF_OCSPS = "O atributo RevocationValues contém menos OCSPs do que o atributo CompleteRevocationRefs.";

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param stackTrace O stack trace da exceção que ocorreu
     */
    public RevocationValuesException(String message, StackTraceElement[] stackTrace) {
        super(message);
        this.setStackTrace(stackTrace);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public RevocationValuesException(String message) {
        super(message);
    }

}
