/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.exceptions;

import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa uma exceção que ocorre na manipulação
 * da Lista de Políticas de Assinatura
 */
public class LpaException extends PbadException {

    private static final long serialVersionUID = 1L;
    public static final String INEXISTENT_PA_OID = "Identificador da política de assinatura não encontrado na lista de políticas de assinatura.";

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public LpaException(String message) {
        super(message);
    }

    /**
     * Construtor
     * @param cause A exceção que ocorreu
     */
    public LpaException(Throwable cause) {
        super(cause);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param stackTrace O stack trace da exceção que ocorreu
     */
    public LpaException(String message, StackTraceElement[] stackTrace) {
        super(message);
        this.setStackTrace(stackTrace);
    }

}
