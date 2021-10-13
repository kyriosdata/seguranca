package br.ufsc.labsec.signature.conformanceVerifier.cades.creator;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesAttributeIncluder;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdMessageDigest;

/**
 * Esta classe é responsável pela criação do atributo IdMessageDigestCreator
 */
public class IdMessageDigestCreator extends Creator {

	/**
	 * Construtor
	 * @param cadesAttributeIncluder Gerenciador de atributos CAdES
	 */
	public IdMessageDigestCreator(CadesAttributeIncluder cadesAttributeIncluder) {
		super(cadesAttributeIncluder);
	}

	/**
	 * Retorna o atributo
	 * @return Um objeto do atributo
	 */
	@Override
	public SignatureAttribute getAttribute() throws NoSuchAlgorithmException, IOException {
		return new IdMessageDigest(cadesAttributeIncluder.getContentToBeSigned());
	}

}
