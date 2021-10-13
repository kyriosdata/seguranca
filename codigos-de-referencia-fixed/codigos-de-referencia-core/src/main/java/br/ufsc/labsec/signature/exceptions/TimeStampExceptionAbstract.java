package br.ufsc.labsec.signature.exceptions;

import java.util.List;

public abstract class TimeStampExceptionAbstract extends SignatureAttributeException {

    public TimeStampExceptionAbstract(String message) {
        super(message);
    }

    public TimeStampExceptionAbstract(String message, StackTraceElement[] stackTrace) {
        super(message, stackTrace);
    }

    public TimeStampExceptionAbstract(String message, Throwable cause) {
        super(message, cause);
    }

    public TimeStampExceptionAbstract(Throwable cause) {
        super(cause);
    }

    public abstract List<Exception> getProblems();
}
