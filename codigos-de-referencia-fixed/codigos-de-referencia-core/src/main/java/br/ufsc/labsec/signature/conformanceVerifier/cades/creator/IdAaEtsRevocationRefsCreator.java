package br.ufsc.labsec.signature.conformanceVerifier.cades.creator;

import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesAttributeIncluder;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsRevocationRefs;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.AlgorithmException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509CRL;
import java.util.List;

/**
 * Esta classe é responsável pela criação do atributo IdAaEtsRevocationRefsCreator
 */
public class IdAaEtsRevocationRefsCreator extends Creator {

	/**
	 * Construtor
	 * @param cadesAttributeIncluder Gerenciador de atributos CAdES
	 */
	public IdAaEtsRevocationRefsCreator(CadesAttributeIncluder cadesAttributeIncluder) {
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
		String algorithm = cadesAttributeIncluder.getComponent().getApplication()
				.getComponentParam(cadesAttributeIncluder.getComponent(), "algorithmOid");

		List<X509CRL> crls = cadesAttributeIncluder.getCRLs();

		return new IdAaEtsRevocationRefs(crls, algorithm);
	}

}
