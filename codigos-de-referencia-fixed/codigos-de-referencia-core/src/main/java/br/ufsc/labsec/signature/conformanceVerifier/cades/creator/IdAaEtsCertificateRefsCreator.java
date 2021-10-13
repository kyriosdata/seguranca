package br.ufsc.labsec.signature.conformanceVerifier.cades.creator;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;

import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesAttributeIncluder;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsCertificateRefs;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.AlgorithmException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe é responsável pela criação do atributo IdAaEtsCertificateRefsCreator
 */
public class IdAaEtsCertificateRefsCreator extends Creator {

	/**
	 * Construtor
	 * @param cadesAttributeIncluder Gerenciador de atributos CAdES
	 */
	public IdAaEtsCertificateRefsCreator(CadesAttributeIncluder cadesAttributeIncluder) {
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
		List<X509Certificate> signCertPath = cadesAttributeIncluder.getCertificateReferences();
		String hashAlgorithmOID = cadesAttributeIncluder.getComponent().getApplication()
				.getComponentParam(cadesAttributeIncluder.getComponent(), "algorithmOid");
		
		List<X509Certificate> certificates = signCertPath.subList(1, signCertPath.size());
		IdAaEtsCertificateRefs certificateRefs = new IdAaEtsCertificateRefs(certificates, hashAlgorithmOID);
		return certificateRefs;
	}

}
