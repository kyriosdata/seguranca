package br.ufsc.labsec.signature.conformanceVerifier.cms.exceptions;

/**
 * Esta classe representa uma exceção causada quando uma assinatura no documento
 * não foi feita com um certificado pertencente à ICP-Brasil.
 */
public class SignatureNotICPBrException extends Exception {

    /**
     * Construtor
     */
    public SignatureNotICPBrException() {
        super();
    }

    /**
     * Construtor
     * @param msg A mensagem de erro
     */
    public SignatureNotICPBrException(String msg) {
        super(msg);
    }

}
