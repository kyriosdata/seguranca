package br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions;

import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa uma exceção causada por um erro
 * na assinatura XAdES.
 */
public class XadesSignatureException extends PbadException {

	private static final long serialVersionUID = 1091783589655855272L;

	/**
	 * Construtor
	 * @param message A mensagem de erro
	 */
	public XadesSignatureException(String message) 
	{
		super(message);
	}

	/**
	 * Construtor
	 * @param cause A exceção que ocorreu
	 */
	public XadesSignatureException(Throwable cause) {
		super(cause);
	}

	/**
	 * Construtor
	 * @param message A mensagem de erro
	 * @param cause A exceção que ocorreu
	 */
	public XadesSignatureException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Construtor
	 * @param message A mensagem de erro
	 * @param stackTrace O stack trace da exceção que ocorreu
	 */
	public XadesSignatureException(String message, StackTraceElement[] stackTrace) 
	{
		super(message);
		this.setStackTrace(stackTrace);
	}

}
