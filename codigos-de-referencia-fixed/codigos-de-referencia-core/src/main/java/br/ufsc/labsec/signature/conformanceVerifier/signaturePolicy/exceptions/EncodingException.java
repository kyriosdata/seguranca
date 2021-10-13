/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.exceptions;

import java.io.PrintStream;
import java.io.PrintWriter;

import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa um erro que ocorre por causa de erro na
 * codificação de um elemento
 */
public class EncodingException extends PbadException {

    private static final long serialVersionUID = 1L;
    /**
     * Exceção que ocorreu
     */
    protected Exception underlyingException;

    /**
     * Construtor
     * @param cause A exceção que ocorreu
     */
    public EncodingException(Throwable cause) {
        super(cause);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param cause A exceção que ocorreu
     */
    public EncodingException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public EncodingException(String message) {
        super(message);
    }

    /**
     * Atribue a exceção que ocorreu
     * @param underlyingException A exceção que ocorreu
     */
    public void setUnderlyingException(Exception underlyingException) {
        this.underlyingException = underlyingException;
    }

    /**
     * Retorna a exceção que ocorreu
     * @return A exceção que ocorreu
     */
    public Exception getUnderlyingException() {
        return this.underlyingException;
    }

    /**
     * Retorna a causa da exceção
     * @return A causa da exceção
     */
    public Throwable getCause() {
        return this.underlyingException.getCause();
    }

    /**
     * Preenche o stack trace da exceção com o estado atual da pilha
     * @return A exceção com o stack trace completo
     */
    public Throwable fillInStackTrace() {
        return this.underlyingException.fillInStackTrace();
    }

    /**
     * Retorna uma mensagem localizada da exceção
     * @return A mensagem localizada
     */
    public String getLocalizedMessage() {
        return this.getLocalizedMessage();
    }

    /**
     * Retorna a mensagem de erro
     * @return A mensagem de erro
     */
    public String getMessage() {
        return this.getMessage();
    }

    /**
     * Retorna o stack trace da exceção que ocorreu
     * @return O stack trace da exceção que ocorreu
     */
    public StackTraceElement[] getStackTrace() {
        return this.getStackTrace();
    }

    /**
     * Atribue a causa da exceção
     * @param cause A causa
     * @return A exceção atualizada
     */
    public Throwable initCause(Throwable cause) {
        return this.initCause(cause);
    }

    /**
     * Exibe o stack trace da exceção que ocorreu
     */
    public void printStackTrace() {
        this.underlyingException.printStackTrace();
    }

    /**
     * Escreve o stack trace da exceção que ocorreu no stream dado
     * @param s O stream onde será escrito o stack trace
     */
    public void printStackTrace(PrintStream s) {
        this.underlyingException.printStackTrace(s);
    }

    /**
     * Escreve o stack trace da exceção que ocorreu no writer dado
     * @param s O writer onde será escrito o stack trace
     */
    public void printStackTrace(PrintWriter s) {
        this.underlyingException.printStackTrace(s);
    }

    /**
     * Atribue o stack trace da exceção
     * @param stackTrace O stack trace
     */
    public void setStackTrace(StackTraceElement[] stackTrace) {
        this.setStackTrace(stackTrace);
    }
}
