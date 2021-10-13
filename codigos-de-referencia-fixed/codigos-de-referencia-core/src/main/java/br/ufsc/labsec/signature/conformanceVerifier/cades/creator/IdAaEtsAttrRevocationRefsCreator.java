package br.ufsc.labsec.signature.conformanceVerifier.cades.creator;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;

import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesAttributeIncluder;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsAttrRevocationRefs;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.AlgorithmException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe é responsável pela criação do atributo IdAaEtsAttrRevocationRefsCreator
 */
public class IdAaEtsAttrRevocationRefsCreator extends Creator {

	/**
	 * Construtor
	 * @param cadesAttributeIncluder Gerenciador de atributos CAdES
	 */
	public IdAaEtsAttrRevocationRefsCreator(CadesAttributeIncluder cadesAttributeIncluder) {
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
			SignatureAttributeException, CertificateEncodingException {
		String hashAlgorithmOID = this.cadesAttributeIncluder.getSignaturePolicyInterface()
				.getHashAlgorithmId();
		// TODO Auto-generated method stub
		return new IdAaEtsAttrRevocationRefs(cadesAttributeIncluder.getCRLs(), hashAlgorithmOID);
	}

}
