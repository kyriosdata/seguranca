/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions;

import java.util.List;

import br.ufsc.labsec.signature.exceptions.TimeStampExceptionAbstract;

/**
 * Esta classe representa uma exceção que ocorre na manipulação
 * de carimbos de tempo.
 */
public class TimeStampException extends TimeStampExceptionAbstract {

    private static final long serialVersionUID = 1L;
    public static final String NOT_FOUND_TIME_STAMP = "Carimbo do tempo não encontrado.";
    public static final String INVALID_TIME_STAMP = "O Carimbo de tempo é inválido.";
    public static final String MALFORMED_TIME_STAMP = "Carimbo de tempo malformado.";
    public static final String VALUE_HASH_ERROR = "O valor do resumo criptográfico do carimbo do tempo é diferente do encontrado na assinatura.";
    public static final String INVALID_ATTRIBUTES_IN_TIMESTAMP = "O carimbo do tempo contém problemas com relação aos seus atributos. Carimbo: ";
    public static final String PROBLEMS_TO_VALIDATE_ATTRIBUTES_IN_TIMESTAMP = "Aconteceram problemas ao validar os atributos do carimbo do tempo. Carimbo: ";
    public static final String PROBLEM_TO_VERIFY_ATTRIBUTES = "Não foi possível validar os atributos do carimbo do tempo. Carimbo: ";
    /**
     * Lista de erros da validação
     */
    private List<Exception> problems;

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public TimeStampException(String message) {
        super(message);
    }

    /**
     * Construtor
     * @param cause A exceção que ocorreu
     */
    public TimeStampException(Throwable cause) {
        super(cause);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param cause A exceção que ocorreu
     */
    public TimeStampException(String message, Throwable cause) {
        super(message, cause.getStackTrace());
    }

    /**
     * Construtor
     * @param cause A exceção que ocorreu
     * @param identifier O identificador do carimbo
     */
    public TimeStampException(Throwable cause, String identifier) {
        super(TimeStampException.PROBLEMS_TO_VALIDATE_ATTRIBUTES_IN_TIMESTAMP + identifier, cause.getStackTrace());
    }

    /**
     * Construtor
     * @param problems A lista de erros da validação
     * @param identifier O identificador do carimbo
     */
    public TimeStampException(List<Exception> problems, String identifier) {
        super(TimeStampException.INVALID_ATTRIBUTES_IN_TIMESTAMP + identifier);
        this.problems = problems;
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param cause A exceção que ocorreu
     * @param identifier O identificador do carimbo
     */
    public TimeStampException(String message, Throwable cause, String identifier) {
        super(message + identifier, cause.getStackTrace());
    }

    /**
     * Retorna a lista de erros da validação
     * @return A lista de erros da validação
     */
    @Override
    public List<Exception> getProblems() {
        return this.problems;
    }
}
