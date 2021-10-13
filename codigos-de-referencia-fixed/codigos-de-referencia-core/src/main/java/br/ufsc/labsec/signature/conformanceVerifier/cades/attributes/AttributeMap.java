/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaContentHint;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaEtsSigPolicyId;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaEtsSignerAttr;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaEtsSignerLocation;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificate;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificateV2;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdContentType;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdMessageDigest;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdSigningTime;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsArchiveTimeStampV2;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsAttrRevocationRefs;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsCertValues;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsCertificateRefs;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsEscTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsRevocationRefs;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsRevocationValues;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaSignatureTimeStampToken;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdCounterSignature;
import br.ufsc.labsec.signature.conformanceVerifier.cms.attributes.signed.RevocationInfoArchival;

import org.w3c.dom.Attr;

/**
 * Esta classe é usada para fazer o mapeamento de atributos entre seus
 * identificadores e suas respectivas classes.
 */
public class AttributeMap {
	static {
		AttributeMap.initialize();
	}
	/**
	 * Mapeamento de atributos entre seus identificadores e suas respectivas
	 * classes
	 */
	private static Map<String, Class<?>> attributeMap;
	/**
	 * Mapeamento de atributos entre seus identificadores e seu nome
	 */
	private static Map<String, String> attributeNameMap;

	/**
	 * Pelo fato de essa classe só possuir métodos estáticos ela não deve ser
	 * construída. <br>
	 * Assim o construtor é privado para não dar a possibilidade de
	 * instanciação.
	 */
	private AttributeMap() {
	}

	/**
	 * Faz o mapeamento dos identificadores de cada atributo com a sua
	 * respectiva classe.
	 */
	public static void initialize() {
		AttributeMap.addAttributeMapping(PKCSObjectIdentifiers.pkcs_9_at_contentType.getId(), IdContentType.class,
				"IdContentType");
		AttributeMap.addAttributeMapping(PKCSObjectIdentifiers.pkcs_9_at_messageDigest.getId(), IdMessageDigest.class,
				"IdMessageDigest");
		AttributeMap.addAttributeMapping(PKCSObjectIdentifiers.id_aa_signingCertificate.getId(),
				IdAaSigningCertificate.class, "IdAaSigningCertificate");
		AttributeMap.addAttributeMapping(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId.getId(), IdAaEtsSigPolicyId.class,
				"IdAaEtsSigPolicyId");
		// AttributeMap.addAttributeMapping(PKCSObjectIdentifiers.id_aa_ets_commitmentType.getId(),
		// IdAaEtsCommitmentType.class);
		AttributeMap.addAttributeMapping(PKCSObjectIdentifiers.id_aa_ets_signerLocation.getId(),
				IdAaEtsSignerLocation.class, "IdAaEtsSignerLocation");
		AttributeMap.addAttributeMapping(PKCSObjectIdentifiers.id_aa_ets_signerAttr.getId(), IdAaEtsSignerAttr.class,
				"IdAaEtsSignerAttr");
		// AttributeMap.addAttributeMapping(PKCSObjectIdentifiers.id_aa_ets_contentTimestamp.getId(),
		// IdAaEtsContentTimeStamp.class);
		AttributeMap.addAttributeMapping(PKCSObjectIdentifiers.id_aa_contentHint.getId(), IdAaContentHint.class,
				"IdAaContentHint");
		AttributeMap.addAttributeMapping(PKCSObjectIdentifiers.pkcs_9_at_counterSignature.getId(),
				IdCounterSignature.class, "IdCounterSignature");
		AttributeMap.addAttributeMapping(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken.getId(),
				IdAaSignatureTimeStampToken.class, "IdAaSignatureTimeStampToken");
		AttributeMap.addAttributeMapping(PKCSObjectIdentifiers.id_aa_ets_certificateRefs.getId(),
				IdAaEtsCertificateRefs.class, "IdAaEtsCertificateRefs");
		AttributeMap.addAttributeMapping(PKCSObjectIdentifiers.id_aa_ets_revocationRefs.getId(),
				IdAaEtsRevocationRefs.class, "IdAaEtsRevocationRefs");
		AttributeMap.addAttributeMapping(PKCSObjectIdentifiers.id_aa_ets_certValues.getId(), IdAaEtsCertValues.class,
				"IdAaEtsCertValues");
		AttributeMap.addAttributeMapping(PKCSObjectIdentifiers.id_aa_ets_revocationValues.getId(),
				IdAaEtsRevocationValues.class, "IdAaEtsRevocationValues");
		AttributeMap.addAttributeMapping(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp.getId(),
				IdAaEtsEscTimeStamp.class, "IdAaEtsEscTimeStamp");
		AttributeMap.addAttributeMapping(IdAaEtsArchiveTimeStampV2.IDENTIFIER, IdAaEtsArchiveTimeStampV2.class,
				"IdAaEtsArchiveTimeStampV2");
		AttributeMap.addAttributeMapping(PKCSObjectIdentifiers.id_aa_signingCertificateV2.getId(),
				IdAaSigningCertificateV2.class, "IdAaSigningCertificateV2");
		AttributeMap.addAttributeMapping("1.2.840.113549.1.9.16.2.45", IdAaEtsAttrRevocationRefs.class,
				"IdAaEtsAttrRevocationRefs");
		AttributeMap.addAttributeMapping(PKCSObjectIdentifiers.pkcs_9_at_signingTime.getId(),
				IdSigningTime.class, "IdSigningTime");
		AttributeMap.addAttributeMapping("1.2.840.113583.1.1.8",
				RevocationInfoArchival.class, "RevocationInfoArchival");
	}

	/**
	 * Informa a classe do atributo pelo seu identificador único.
	 * @param attributeIdentifier O Identificador único do atributo. Ex.: "1.2.840.113549.1.1.5".
	 * @return A classe do atributo
	 */
	static public Class<?> getAttributeClass(String attributeIdentifier) {
		Class<?> retorno = null;
		if (AttributeMap.attributeMap != null) {
			retorno = AttributeMap.attributeMap.get(attributeIdentifier);
		}
		return retorno;
	}

	/**
	 * Permite adicionar um novo atributo no mapeamento de atributos.
	 * @param attributeIdentifier O Identificador único do attributo. Ex.:
	 *            "1.2.840.113549.1.1.5".
	 * @param attributeClass A classe do atributo correspondente ao identificador único
	 *            informado.
	 */
	static public void addAttributeMapping(String attributeIdentifier, Class<?> attributeClass, String attributeName) {
		if (AttributeMap.attributeMap == null)
			AttributeMap.attributeMap = new HashMap<String, Class<?>>();
		if (AttributeMap.attributeNameMap == null)
			AttributeMap.attributeNameMap = new HashMap<String, String>();
		AttributeMap.attributeMap.put(attributeIdentifier, attributeClass);
		AttributeMap.attributeNameMap.put(attributeIdentifier, attributeName);
	}

	/**
	 * Informa os nomes dos atributos da lista
	 * @param attributes A lista de OIDs de atributos
	 * @return Lista com os nomes dos atributos
	 */
	public static String translateNames(List<String> attributes) {
		List<String> attributeNames = new ArrayList<>();
		for (String attribute : attributes) {
			attributeNames.add(AttributeMap.attributeNameMap.get(attribute));
		}
		return attributeNames.toString();
	}

	/**
	 * Informa o nome do atributo pelo seu identificador único.
	 * @param mandatedAttribute O identificador do atributo
	 * @return O nome do atributo
	 */
	public static String translateName(String mandatedAttribute) {
		return AttributeMap.attributeNameMap.get(mandatedAttribute);
	}
}
