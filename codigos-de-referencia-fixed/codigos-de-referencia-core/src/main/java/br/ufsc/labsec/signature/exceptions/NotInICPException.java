package br.ufsc.labsec.signature.exceptions;

public class NotInICPException extends SignatureAttributeException {

    private static final long serialVersionUID = 1L;
    public static final String TIMESTAMP_SIGNATURE = "O carimbo de tempo foi assinado com um certificado que não pertence à ICP-Brasil.";

    public NotInICPException(String message) {
        super(message);
    }

    public NotInICPException(Throwable cause) {
        super(cause);
    }

    public NotInICPException(String message, Throwable cause) {
        super(message, cause);
    }
}
