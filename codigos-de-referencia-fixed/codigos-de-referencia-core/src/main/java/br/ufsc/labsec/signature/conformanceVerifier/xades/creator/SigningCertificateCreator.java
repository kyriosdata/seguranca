package br.ufsc.labsec.signature.conformanceVerifier.xades.creator;

import java.security.cert.X509Certificate;
import java.util.ArrayList;

import javax.xml.crypto.dsig.DigestMethod;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractXadesSigner;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SigningCertificate;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe é responsável pela criação do atributo SigningCertificate
 */
public class SigningCertificateCreator extends Creator {

	/**
	 * Construtor
	 * @param xadesSigner Assinador XAdES
	 */
	public SigningCertificateCreator(AbstractXadesSigner xadesSigner) {
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
		
		SigningCertificate signingCertificate = null;
		
		try {
			String hashAlgorithmOID = this.xadesSigner.getComponent().signaturePolicyInterface.getHashAlgorithmId();

			ArrayList<X509Certificate> signingCertificateCertPath = new ArrayList<X509Certificate>();
			X509Certificate signerCertificate = xadesSigner.getComponent().privateInformation.getCertificate();
			signingCertificateCertPath.add(signerCertificate);

			signingCertificate = new SigningCertificate(signingCertificateCertPath, hashAlgorithmOID);
		} catch (SignatureAttributeException e) {
			throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + SigningCertificate.IDENTIFIER, e);
		}
		
		return signingCertificate;
	}

}
