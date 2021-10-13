package br.ufsc.labsec.signature.conformanceVerifier.cades.creator;

import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesAttributeIncluder;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdContentType;

/**
 * Esta classe é responsável pela criação do atributo IdContentTypeCreator
 */
public class IdContentTypeCreator extends Creator{

	/**
	 * Construtor
	 * @param cadesAttributeIncluder Gerenciador de atributos CAdES
	 */
	public IdContentTypeCreator(CadesAttributeIncluder cadesAttributeIncluder) {
		super(cadesAttributeIncluder);
	}

	/**
	 * Retorna o atributo
	 * @return Um objeto do atributo
	 */
	@Override
	public SignatureAttribute getAttribute() {
		return new IdContentType("1.2.840.113549.1.7.1");
	}


}
