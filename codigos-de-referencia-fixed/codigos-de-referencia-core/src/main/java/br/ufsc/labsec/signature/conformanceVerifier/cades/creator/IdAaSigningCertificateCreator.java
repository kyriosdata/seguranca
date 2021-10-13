package br.ufsc.labsec.signature.conformanceVerifier.cades.creator;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import org.bouncycastle.cms.CMSSignedDataGenerator;

import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesAttributeIncluder;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificate;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificateV2;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.AlgorithmException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe é responsável pela criação do atributo IdAaSigningCertificateCreator
 */
public class IdAaSigningCertificateCreator extends Creator {

	/**
	 * Construtor
	 * @param cadesAttributeIncluder Gerenciador de atributos CAdES
	 */
	public IdAaSigningCertificateCreator(
			CadesAttributeIncluder cadesAttributeIncluder) {
		super(cadesAttributeIncluder);
		// TODO Auto-generated constructor stub
	}

	/**
	 * Retorna o atributo
	 * @return Um objeto do atributo
	 */
	@Override
	public SignatureAttribute getAttribute() throws NoSuchAlgorithmException,
			IOException, AlgorithmException, EncodingException,
			SignatureAttributeException {
		String hashAlgorithmOID = this.cadesAttributeIncluder
				.getSignaturePolicyInterface().getHashAlgorithmId();

		X509Certificate signerCertificate = this.cadesAttributeIncluder
				.getComponent().privateInformation.getCertificate();
		ArrayList<X509Certificate> signingCertificateCertPath = new ArrayList<X509Certificate>();
		signingCertificateCertPath.add(signerCertificate);
		if (this.cadesAttributeIncluder.getSignaturePolicyInterface()
				.getMandatedSignedAttributeList()
				.contains(IdAaSigningCertificateV2.IDENTIFIER)
				&& hashAlgorithmOID.equals(CMSSignedDataGenerator.DIGEST_SHA1)) {
			throw new SignatureAttributeException("Não é possível criar uma assinatura com atributo signingCertificaV2 com algoritmo de hash sha-1.");
		}
		if (hashAlgorithmOID.equals(CMSSignedDataGenerator.DIGEST_SHA1)) {
			return new IdAaSigningCertificate(signingCertificateCertPath);
		} else {
			return new IdAaSigningCertificateV2(hashAlgorithmOID,
					signingCertificateCertPath);
		}

	}

}
