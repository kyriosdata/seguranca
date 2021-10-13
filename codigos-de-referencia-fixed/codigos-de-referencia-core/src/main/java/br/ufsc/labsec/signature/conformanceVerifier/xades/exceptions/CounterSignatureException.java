/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions;

import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa uma exceção que ocorre na manipulação
 * de contra-assinaturas
 */
public class CounterSignatureException extends PbadException {

    private static final long serialVersionUID = 1L;
    public static final String NOT_EXIST_COUNTERSIGNATURE = "Não existem contra assinaturas para este assinante";
    public static final String COUNTER_SIGNER_NOT_FOUND = "Contra assinante inexistente para esta assinatura";
    public static final String SIGNING_CERTIFICATE_NOT_FOUND = "Não existe informação suficiente para encontrar o certificado do assinante";

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public CounterSignatureException(String message) {
        super(message);
    }

    /**
     * Construtor
     * @param cause A exceção que ocorreu
     */
    public CounterSignatureException(Throwable cause) {
        super(cause);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param cause A exceção que ocorreu
     */
    public CounterSignatureException(String message, Throwable cause) {
        super(message, cause);
    }

}
