package br.ufsc.labsec.signature.conformanceVerifier.cades;

import java.io.File;

import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdCounterSignature;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.NodeOperationException;

/**
 * Esta classe representa uma assinatura que será assinada. Seu modo será
 *  <b>sempre COUNTERSIGNED</b>.
 * Estende {@link CadesContentToBeSigned}
 */
public class CadesSignatureToBeSigned extends CadesContentToBeSigned
{
	/**
	 * Assinatura CAdES que será contra-assinada
	 */
	protected Signature signatureToBeCounterSigned;

	/**
	 * Essa classe representa uma assinatura que será assinada. Seu modo será
	 * <b>sempre COUNTERSIGNED</b>
	 *
	 * @param signatureToBeCounterSigned Assinatura que será contra-assinada
	 */
	public CadesSignatureToBeSigned(CadesSignatureInformation signatureToBeCounterSigned)
	{
		super(IdCounterSignature.IDENTIFIER, signatureToBeCounterSigned.getSignatureValue(), 
				SignatureModeCAdES.DETACHED);
		this.signatureToBeCounterSigned = signatureToBeCounterSigned;
	}

	/**
	 * Construtor
	 * @param signatureToBeCounterSigned Assinatura que será contra-assinada
	 * @param provider O Provider a ser utilizado na assinatura
	 */
	public CadesSignatureToBeSigned(CadesSignatureInformation signatureToBeCounterSigned, String provider)
	{
		super(IdCounterSignature.IDENTIFIER, signatureToBeCounterSigned.getSignatureValue(), 
				SignatureModeCAdES.DETACHED, provider);
		this.signatureToBeCounterSigned = signatureToBeCounterSigned;
	}

	/**
	 * Construtor
	 * @param contentFile Arquivo com o conteúdo a ser assinado
	 * @param mode Modo da assinatura
	 */
	public CadesSignatureToBeSigned(File contentFile, SignatureModeCAdES mode) {
		super(contentFile, mode);
	}

	/**
	 * Obtém a assinatura que está sendo contra assinada
	 * @return Assinatura que está sendo contra-assinada,
	 * retorna nulo se não estiver sendo criada uma contra assinatura
	 */
	public CadesSignatureInformation getSignatureToBeCounterSigned()
	{
		return (CadesSignatureInformation) signatureToBeCounterSigned;
	}
}
