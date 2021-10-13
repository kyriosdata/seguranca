package br.ufsc.labsec.signature.conformanceVerifier.xades.creator;

import java.security.cert.X509CRL;
import java.util.List;

import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractXadesSigner;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.RevocationValues;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe é responsável pela criação do atributo RevRefs
 */
public class RevocationValuesCreator extends Creator {

	/**
	 * Construtor
	 * @param xadesSigner Assinador XAdES
	 */
	public RevocationValuesCreator(AbstractXadesSigner xadesSigner) {
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
		RevocationValues revocationValues;
		try {
			
			List<X509CRL> crlValues = xadesSigner.getCRLs();
			List<BasicOCSPResponse> basicOCSPResponseValues = null; //TODO
			
			revocationValues = new RevocationValues(crlValues, basicOCSPResponseValues);
		} catch (SignatureAttributeException e) {
			throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + RevocationValues.IDENTIFIER, e);
		}
		
		return revocationValues;
	}

}
