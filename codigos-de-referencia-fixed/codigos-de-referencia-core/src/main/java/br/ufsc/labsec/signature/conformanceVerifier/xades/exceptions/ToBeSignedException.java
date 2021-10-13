/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions;

import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa uma exceção que ocorreu durante o processo
 * de assinatura de um documento
 */
public class ToBeSignedException extends PbadException {

    private static final long serialVersionUID = 1L;
    /**
     * A exceção que ocorreu durante o processo de assinatura
     */
    private Throwable cause;

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public ToBeSignedException(String message) {
        super(message);
    }

    /**
     * Construtor
     * @param cause A exceção que ocorreu
     */
    public ToBeSignedException(Throwable cause) {
        super(cause);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param cause A exceção que ocorreu
     */
    public ToBeSignedException(String message, Throwable cause) {
        super(message);
        this.cause = cause;
    }

    /**
     * Retorna a causa da exceção
     * @return A causa da exceção
     */
    @Override
    public Throwable getCause() {
        return this.cause;
    }
}
