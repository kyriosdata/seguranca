package br.ufsc.labsec.signature.conformanceVerifier.xades.creator;

import org.bouncycastle.util.encoders.Base64;

import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.SignaturePolicyInterface.AdESType;
import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractXadesSigner;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SignaturePolicyIdentifier;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe é responsável pela criação do atributo SignaturePolicyIdentifier
 */
public class SignaturePolicyIdentifierCreator extends Creator {

	/**
	 * Construtor
	 * @param xadesSigner Assinador XAdES
	 */
	public SignaturePolicyIdentifierCreator(AbstractXadesSigner xadesSigner) {
		super(xadesSigner);
	}

	/**
	 * Retorna o atributo
	 * @return Um objeto do atributo
	 * @throws SignatureAttributeException Exceção caso ocorra algum erro durante
	 * a construção do objeto
	 */
	@Override
	public SignatureAttribute getAttribute() throws SignatureAttributeException {
		
		SignaturePolicyInterface policyInterface = xadesSigner.getComponent().signaturePolicyInterface;
		
		SignaturePolicyIdentifier policyIdentifier = null;

		//  SignaturePolicyIdentifier(String sigPolicyId, String digestMethodId, byte[] policyHash, String policyUrl)
		policyIdentifier =  new SignaturePolicyIdentifier(policyInterface.getPolicyId(), policyInterface.getHashAlgorithmId(), 
				Base64.encode(policyInterface.getSignPolicyHash()),
				policyInterface.getURL(AdESType.XAdES));
		
		return policyIdentifier;
		
	}

}
