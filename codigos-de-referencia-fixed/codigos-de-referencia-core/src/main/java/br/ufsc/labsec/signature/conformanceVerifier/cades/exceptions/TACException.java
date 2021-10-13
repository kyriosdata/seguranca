package br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions;

import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe representa uma exceção causada durante a validação do certificado
 * do assinante de um carimbo de tempo
 */
public class TACException extends SignatureAttributeException {

	private static final long serialVersionUID = -1360535575194743581L;

	/**
	 * Construtor
	 * @param message A mensagem de erro
	 */
	public TACException(String message) {
		super(message);
	}

}
