package br.ufsc.labsec.signature.conformanceVerifier.cms.exceptions;

import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa uma exceção causada durante a verificação
 * de uma assinatura CMS.
 */
public class CmsSignatureException extends PbadException {

    private static final long serialVersionUID = 1L;

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public CmsSignatureException(String message) {
        super(message);
    }

    /**
     * Construtor
     * @param cause A exceção que ocorreu durante a verificação
     */
    public CmsSignatureException(Throwable cause) {
        super(cause);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param cause  A exceção que ocorreu durante a verificação
     */
    public CmsSignatureException(String message, Throwable cause) {
        super(message, cause);
    }

}
