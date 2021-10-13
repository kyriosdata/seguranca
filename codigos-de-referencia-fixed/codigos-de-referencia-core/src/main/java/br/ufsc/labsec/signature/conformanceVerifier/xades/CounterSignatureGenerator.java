package br.ufsc.labsec.signature.conformanceVerifier.xades;

import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SignaturePolicyIdentifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.LpaException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.ToBeSignedException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.EncodingException;

/**
 * Esta classe adiciona uma contra-assinatura XAdES.
 * Estende {@link SignatureContainerGenerator}.
 */

public class CounterSignatureGenerator extends SignatureContainerGenerator {

	/**
	 * Construtor
	 * @param signaturePolicyIdentifier O identificador da política de assinatura a ser utilizada
	 * @param xadesSignature Componente de assinatura XAdES
	 */
	public CounterSignatureGenerator(SignaturePolicyIdentifier signaturePolicyIdentifier,
			XadesSignatureComponent xadesSignature) {
		super(signaturePolicyIdentifier, xadesSignature);
	}

	/**
	 * Gera a contra assinatura
	 * 
	 * @return {@link SignatureContainer} que contém a assinatura gerada
	 * @throws PbadException exceção em caso de erro durante a geração da assinatura
	 */
	public Signature counterSign() throws PbadException {
		Signature signature = super.sign().getSignatureAt(0);
		Signature resultingSignature = null;
		resultingSignature = signature;
		return resultingSignature;
	}

}
