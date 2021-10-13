package br.ufsc.labsec.signature.conformanceVerifier.cades;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.tsp.TSPException;

import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
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
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsAttrCertificateRefs;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsAttrRevocationRefs;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsCertValues;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsCertificateRefs;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsEscTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsRevocationRefs;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsRevocationValues;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaSignatureTimeStampToken;
import br.ufsc.labsec.signature.conformanceVerifier.cades.creator.Creator;
import br.ufsc.labsec.signature.conformanceVerifier.cades.creator.IdAaContentHintCreator;
import br.ufsc.labsec.signature.conformanceVerifier.cades.creator.IdAaEtsArchiveTimeStampV2Creator;
import br.ufsc.labsec.signature.conformanceVerifier.cades.creator.IdAaEtsCertValuesCreator;
import br.ufsc.labsec.signature.conformanceVerifier.cades.creator.IdAaEtsCertificateRefsCreator;
import br.ufsc.labsec.signature.conformanceVerifier.cades.creator.IdAaEtsEscTimeStampCreator;
import br.ufsc.labsec.signature.conformanceVerifier.cades.creator.IdAaEtsRevocationRefsCreator;
import br.ufsc.labsec.signature.conformanceVerifier.cades.creator.IdAaEtsRevocationValuesCreator;
import br.ufsc.labsec.signature.conformanceVerifier.cades.creator.IdAaEtsSignerLocationCreator;
import br.ufsc.labsec.signature.conformanceVerifier.cades.creator.IdAaSignatureTimeStampCreator;
import br.ufsc.labsec.signature.conformanceVerifier.cades.creator.IdAaSigningCertificateCreator;
import br.ufsc.labsec.signature.conformanceVerifier.cades.creator.IdContentTypeCreator;
import br.ufsc.labsec.signature.conformanceVerifier.cades.creator.IdMessageDigestCreator;
import br.ufsc.labsec.signature.conformanceVerifier.cades.creator.IdSigningTimeCreator;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 *  Esta classe mapeia o OID de um atributo para o seu nome e um atributo a seu respectivo Creator.
 */
public class AttributeFactory {

	/**
	 * Mapa que relaciona identificadores de atributos aos seus nomes
	 */
	private static Map<String,String> oidToName;
	
	public static final String id_aa_ets_archiveTimeStampV2 = "IdAaEtsArchiveTimeStampV2";
	public static final String id_aa_ets_revocationValues = "IdAaEtsRevocationValues";
	public static final String id_aa_ets_certValues = "IdAaEtsCertValues";
	public static final String id_aa_ets_escTimeStamp = "IdAaEtsEscTimeStamp";
	public static final String id_aa_ets_attrRevocationRefs = "IdAaEtsAttrRevocationRefs";
	public static final String id_aa_ets_attrCertificateRefs = "IdAaEtsAttrCertificateRefs";
	public static final String id_aa_ets_revocationRefs = "IdAaEtsRevocationRefs";
	public static final String id_aa_ets_CertificateRefs = "IdAaEtsCertificateRefs";
	public static final String id_aa_ets_signerLocation = "IdAaEtsSignerLocation";
	public static final String id_aa_signatureTimeStamp = "IdAaSignatureTimeStamp";
	
	public static final String id_signingTime = "IdSigningTime";
	public static final String id_aa_ets_signerAttr = "IdAaEtsSignerAttr";
	public static final String id_contentType = "IdContentType";
	public static final String id_aa_contentHint = "IdAaContentHint";
	public static final String id_messageDigest = "IdMessageDigest";
	public static final String id_aa_signingCertificate = "IdAaSigningCertificate";
	
	public static final String id_aa_ets_sigPolicyId = "IdAaEtsSigPolicyId";
	
	
	static{
		oidToName = new HashMap<String, String>();
		oidToName.put(IdAaEtsArchiveTimeStampV2.IDENTIFIER, id_aa_ets_archiveTimeStampV2);
		oidToName.put(IdAaEtsRevocationValues.IDENTIFIER, id_aa_ets_revocationValues);
		oidToName.put(IdAaEtsCertValues.IDENTIFIER, id_aa_ets_certValues);
		oidToName.put(IdAaEtsEscTimeStamp.IDENTIFIER, id_aa_ets_escTimeStamp);
		oidToName.put(IdAaEtsAttrRevocationRefs.IDENTIFIER, id_aa_ets_attrRevocationRefs);
		oidToName.put(IdAaEtsAttrCertificateRefs.IDENTIFIER, id_aa_ets_attrCertificateRefs);
		oidToName.put(IdAaEtsRevocationRefs.IDENTIFIER, id_aa_ets_revocationRefs);
		oidToName.put(IdAaEtsCertificateRefs.IDENTIFIER, id_aa_ets_CertificateRefs);
		oidToName.put(IdAaEtsSignerLocation.IDENTIFIER, id_aa_ets_signerLocation);
		oidToName.put(IdSigningTime.IDENTIFIER, id_signingTime);
		oidToName.put(IdAaEtsSignerAttr.IDENTIFIER, id_aa_ets_signerAttr);
		oidToName.put(IdAaSignatureTimeStampToken.IDENTIFIER, id_aa_signatureTimeStamp);
		
		oidToName.put(IdContentType.IDENTIFIER,id_contentType);
		oidToName.put(IdAaContentHint.IDENTIFIER,id_aa_contentHint);
		oidToName.put(IdMessageDigest.IDENTIFIER,id_messageDigest);
		oidToName.put(IdAaSigningCertificate.IDENTIFIER,id_aa_signingCertificate);
		oidToName.put(IdAaSigningCertificateV2.IDENTIFIER,id_aa_signingCertificate);
		
		oidToName.put(IdAaEtsSigPolicyId.IDENTIFIER, id_aa_ets_sigPolicyId);
	}

	/**
	 * Gerenciador de atributos
	 */
	private CadesAttributeIncluder abstractCadesSigner;
	/**
	 * Mapa que relaciona identificadores aos seus objetos {@link Creator}
	 */
	private HashMap<String, Creator> attributeFactoryMap;
	/**
	 * Conjunto de atributos assinados
	 */
	private Set<String> signedAttributes;

	/**
	 * Construtor
	 * @param abstractCadesSigner Gerenciador de atributos
	 */
	  public AttributeFactory(CadesAttributeIncluder abstractCadesSigner) {
	    	this.abstractCadesSigner = abstractCadesSigner;
	    	initializeAttributeFactoryMap();  	
	    	
	    	signedAttributes = new HashSet<>();
	    	
	    	
	    	
	    	signedAttributes.add(id_contentType);
	    	signedAttributes.add(id_aa_contentHint);
	    	signedAttributes.add(id_messageDigest);
	    	signedAttributes.add(id_aa_signingCertificate);
	    	signedAttributes.add(id_aa_ets_sigPolicyId);
	    	signedAttributes.add(id_aa_ets_signerLocation);
	    	signedAttributes.add(id_signingTime);
//	    	signedAttributes.add(id_aa_ets_signerAttr);
	    	
	    	
	    	
		}

	/**
	 * Inicializa o mapa que relaciona identificadores aos seus objetos {@link Creator}
	 */
	private void initializeAttributeFactoryMap() {
		this.attributeFactoryMap = new HashMap<String, Creator>();
		
		this.attributeFactoryMap.put(id_contentType, new IdContentTypeCreator(abstractCadesSigner));
		this.attributeFactoryMap.put(id_aa_contentHint, new IdAaContentHintCreator(abstractCadesSigner));
		this.attributeFactoryMap.put(id_signingTime, new IdSigningTimeCreator(abstractCadesSigner));
		this.attributeFactoryMap.put(id_messageDigest, new IdMessageDigestCreator(abstractCadesSigner));
		this.attributeFactoryMap.put(id_aa_signingCertificate, new IdAaSigningCertificateCreator(abstractCadesSigner));
		this.attributeFactoryMap.put(id_aa_ets_signerLocation, new IdAaEtsSignerLocationCreator(abstractCadesSigner));
		
		this.attributeFactoryMap.put(id_aa_ets_archiveTimeStampV2, new IdAaEtsArchiveTimeStampV2Creator(abstractCadesSigner));
		this.attributeFactoryMap.put(id_aa_ets_revocationValues, new IdAaEtsRevocationValuesCreator(abstractCadesSigner));
		this.attributeFactoryMap.put(id_aa_ets_certValues, new IdAaEtsCertValuesCreator(abstractCadesSigner));
		this.attributeFactoryMap.put(id_aa_ets_escTimeStamp, new IdAaEtsEscTimeStampCreator(abstractCadesSigner));
		this.attributeFactoryMap.put(id_aa_ets_revocationRefs, new IdAaEtsRevocationRefsCreator(abstractCadesSigner));
		this.attributeFactoryMap.put(id_aa_ets_CertificateRefs,new IdAaEtsCertificateRefsCreator(abstractCadesSigner));
		
		this.attributeFactoryMap.put(id_aa_signatureTimeStamp, new IdAaSignatureTimeStampCreator(abstractCadesSigner));
//		this.attributeFactoryMap.put(id_aa_ets_signerAttr, new IdAaEtsSignerAttrCreator(abstractCadesSigner));	
//		this.attributeFactoryMap.put(id_aa_ets_attrRevocationRefs, new IdAaEtsAttrRevocationRefsCreator(abstractCadesSigner));
//		this.attributeFactoryMap.put(id_aa_ets_attrCertificateRefs, new IdAaEtsAttrCertificateRefsCreator(abstractCadesSigner));
		
		
		
	}

	/**
	 * Retorna um atributo
	 * @param attributeName o identificador do atributo
	 * @return o atributo correspondente ao identificador ou nulo se não for encontrado
	 * @throws SignatureAttributeException exceção em caso de erro na busca pelo atributo
	 */
	public SignatureAttribute getAttribute(String attributeName) throws NoSuchAlgorithmException, IOException, CertificateEncodingException, PbadException, TSPException{
		if(attributeFactoryMap.containsKey(attributeName.trim())){	
			return attributeFactoryMap.get(attributeName.trim()).getAttribute();	
		}
		return null;
	}

	/**
	 * Retorna o nome do atributo do OID dado
	 * @param oid O OID do atributo
	 * @return O nome do atributo
	 */
	public static String translateOid(String oid){
		return oidToName.get(oid);
	}

	/**
	 * Verifica se o atributo é assinado
	 * @param attribute o identificador do atributo a ser verificado
	 * @return indica se o atributo é assinado
	 */
	public boolean isSigned(String attribute) {
		return signedAttributes.contains(attribute.trim());
	}
	

}
