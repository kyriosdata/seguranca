/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions;

import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa uma exceção causada por algum erro
 * relacionado ao modo de assinatura
 */
public class SignatureModeException extends PbadException {

    private static final long serialVersionUID = 1L;
    public static final String INVALID_MODE = "Modo de assinatura invalido para esse tipo de dado.";
    public static final String THIS_MODE_NEED_OPERATIONS = "Para assinar de forma enveloped deve ser informada pelo menos uma operação";

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public SignatureModeException(String message) {
        super(message);
    }

    /**
     * Construtor
     * @param cause A exceção que ocorreu
     */
    public SignatureModeException(Throwable cause) {
        super(cause);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param cause A exceção que ocorreu
     */
    public SignatureModeException(String message, Throwable cause) {
        super(message, cause);
    }
}
