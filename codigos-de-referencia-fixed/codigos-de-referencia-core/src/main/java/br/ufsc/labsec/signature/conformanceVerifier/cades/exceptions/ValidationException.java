/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions;

import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa uma exceção que indica que aconteceu algum erro de validação.
 * O erro será indicado melhor pelas suas subclasses, que cada uma indica um conjunto de
 * erros comuns que pode acontecer na validação.
 * 
 */
public class ValidationException extends PbadException {

    private static final long serialVersionUID = 1L;

    public static final String OID_ERROR = "Não existe PA com tal oid";
    public static final String STANDART_ERROR = "A validação falhou.";
    public static final String OCSP_ERROR = "Você precisa informar as respostas OCSPs ao validador.";

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public ValidationException(String message) {
        super(message);
    }

    /**
     * Construtor.
     * Utiliza a mensagem padrão de erro
     */
    public ValidationException() {
        super(ValidationException.STANDART_ERROR);
    }

}
