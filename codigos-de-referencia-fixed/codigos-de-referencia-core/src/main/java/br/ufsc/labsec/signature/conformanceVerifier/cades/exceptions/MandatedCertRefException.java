/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions;

import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe representa uma exceção que ocorre quando o valor do atributo
 * MandatedCertRef não corresponde com os dados na assinatura
 */
public class MandatedCertRefException extends SignatureAttributeException {

    private static final long serialVersionUID = 1L;
    public static final String ISNT_SIGNER_ONLY = "De acordo com a Política de Assinatura, o valor do MandatedCertRef é SignerOnly, "
            + "porém, o atributo SigningCertificate tem zero ou mais de um certificado.";
    public static final String ISNT_FULL_PATH = "De acordo com a Política de Assinatura, o valor do MandatedCertRef é FullPath, "
            + "porém, o atributo SigningCertificate tem apenas um certificado.";

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public MandatedCertRefException(String message) {
        super(message);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param stackTrace O stack trace da exceção que ocorreu
     */
    public MandatedCertRefException(String message, StackTraceElement[] stackTrace) {
        super(message);
        this.setStackTrace(stackTrace);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param index O índice do atributo
     */
    public MandatedCertRefException(String message, int index) {
        super(message + index);
    }
}
