/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions;

import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa uma exceção causada por um
 * algoritmo inválido.
 */
public class AlgorithmException extends PbadException {

    private static final long serialVersionUID = -7524169009228118875L;

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param stackTrace O stack trace da exceção gerada
     */
    public AlgorithmException(String message, StackTraceElement[] stackTrace) {
        super(message);
        this.setStackTrace(stackTrace);
    }

    /**
     * Construtor
     * @param cause A exceção que ocorreu
     */
    public AlgorithmException(Throwable cause) {
        super(cause);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param cause  A exceção que ocorreu durante a verificação
     */
    public AlgorithmException(String message, Throwable cause) {
        super(message, cause);
    }

}
