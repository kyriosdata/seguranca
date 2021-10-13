package br.ufsc.labsec.signature.conformanceVerifier.pades.exceptions;

import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa uma exceção causada por algum erro
 * no dicionário da assinatura, como alguma entrada inválida.
 */
public class DictionaryException extends PbadException {

    private static final long serialVersionUID = 1L;

	/**
	 * Construtor
	 * @param message A mensagem de erro
	 * @param cause  A exceção que ocorreu durante a verificação
	 */
    public DictionaryException(String message, Throwable cause) {
        super(message, cause);
    }

	/**
	 * Construtor
	 * @param cause A exceção que ocorreu durante a verificação
	 */
    public DictionaryException(Throwable cause) {
        super(cause);
    }

	/**
	 * Construtor
	 * @param message A mensagem de erro
	 */
    public DictionaryException(String message) {
        super(message);
    }

}
