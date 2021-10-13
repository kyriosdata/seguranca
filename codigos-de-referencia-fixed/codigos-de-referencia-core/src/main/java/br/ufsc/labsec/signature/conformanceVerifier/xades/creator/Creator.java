package br.ufsc.labsec.signature.conformanceVerifier.xades.creator;

import java.util.HashMap;
import java.util.Map;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractXadesSigner;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CertificateValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CompleteCertificateRefs;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CompleteRevocationRefs;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.RevocationValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.SignatureTimeStamp;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe engloba métodos em comum entre Creators de atributos
 */
public abstract class Creator {

	/**
	 * Assinador XAdES
	 */
	protected AbstractXadesSigner xadesSigner;
	/**
	 * Mapa que relaciona o identificador de atributos com seu nome
	 */
	protected Map<String, String> attributesNames;

	/**
	 * Construtor
	 * @param xadesSigner Assinador XAdES
	 */
	public Creator(AbstractXadesSigner xadesSigner){
		this.xadesSigner = xadesSigner;
		
		attributesNames = new HashMap<>();
		
		attributesNames.put(CompleteCertificateRefs.IDENTIFIER, "IdAaEtsCertificateRefs");
		attributesNames.put(CompleteRevocationRefs.IDENTIFIER, "IdAaEtsRevocationRefs");
		attributesNames.put(CertificateValues.IDENTIFIER, "IdAaEtsCertValues");
		attributesNames.put(RevocationValues.IDENTIFIER, "IdAaEtsRevocationValues");
		attributesNames.put(SignatureTimeStamp.IDENTIFIER, "IdAaSignatureTimeStamp");
//		attributesNames.put(AttributeCertificateRefs.IDENTIFIER, "IdAaEtsAttrCertificateRefs");
		//TODO ao criar novos atributos adicionar aqui
	}

	/**
	 * Retorna o nome do atributo
	 * @param attribute O identificador do atributo
	 * @return O nome do atributo
	 */
	public String getCadesAttributeName(String attribute) {
		return this.attributesNames.get(attribute);
	}

	/**
	 * Retorna o atributo
	 * @return Um objeto do atributo
	 * @throws SignatureAttributeException Exceção caso ocorra algum erro durante
	 * a construção do objeto
	 */
	public abstract SignatureAttribute getAttribute() throws SignatureAttributeException;
	
}
