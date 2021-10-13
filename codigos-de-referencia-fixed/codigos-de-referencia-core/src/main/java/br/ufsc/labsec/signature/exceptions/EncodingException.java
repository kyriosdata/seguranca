/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.exceptions;

import java.io.PrintStream;
import java.io.PrintWriter;

public class EncodingException extends PbadException {

    private static final long serialVersionUID = 1L;
    protected Exception underlyingException;

    public EncodingException(Throwable cause) {
        super(cause);
    }

    public EncodingException(String message, Throwable cause) {
        super(message, cause);
    }

    public EncodingException(String message) {
        super(message);
    }

    public void setUnderlyingException(Exception underlyingException) {
        this.underlyingException = underlyingException;
    }

    public Exception getUnderlyingException() {
        return this.underlyingException;
    }

    public Throwable getCause() {
        return this.underlyingException.getCause();
    }

    public Throwable fillInStackTrace() {
        return this.underlyingException.fillInStackTrace();
    }

    public String getLocalizedMessage() {
        return this.getLocalizedMessage();
    }

    public String getMessage() {
        return this.getMessage();
    }

    public StackTraceElement[] getStackTrace() {
        return this.getStackTrace();
    }

    public Throwable initCause(Throwable cause) {
        return this.initCause(cause);
    }

    public void printStackTrace() {
        this.underlyingException.printStackTrace();
    }

    public void printStackTrace(PrintStream s) {
        this.underlyingException.printStackTrace(s);
    }

    public void printStackTrace(PrintWriter s) {
        this.underlyingException.printStackTrace(s);
    }

    public void setStackTrace(StackTraceElement[] stackTrace) {
        this.setStackTrace(stackTrace);
    }
}
