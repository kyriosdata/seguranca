package br.ufsc.labsec.signature.conformanceVerifier.xades.creator;

import java.security.cert.X509Certificate;
import java.util.List;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractXadesSigner;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CertificateValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CompleteCertificateRefs;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe é responsável pela criação do atributo CompleteCertRefs
 */
public class CompleteCertificateRefsCreator extends Creator {

	/**
	 * Construtor
	 * @param xadesSigner Assinador XAdES
	 */
	public CompleteCertificateRefsCreator(AbstractXadesSigner xadesSigner) {
		super(xadesSigner);
	}

	/**
	 * Retorna o atributo
	 * @return Um objeto do atributo
	 * @throws SignatureAttributeException Exceção caso ocorra algum erro durante
	 * a construção do objeto
	 */
	@Override
	public SignatureAttribute getAttribute() throws SignatureAttributeException{
		List<X509Certificate> signCertPath = xadesSigner.getCertificateReferences();
		String hashAlgorithmOID = this.xadesSigner.getComponent().getApplication()
				.getComponentParam(this.xadesSigner.getComponent(), "algorithmOid");

		List<X509Certificate> certificates = signCertPath.subList(1, signCertPath.size());
		CompleteCertificateRefs certificateRefs = new CompleteCertificateRefs(certificates, hashAlgorithmOID);

		return certificateRefs;
	}

}
