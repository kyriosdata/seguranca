package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.DataObjectFormat;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SignaturePolicyIdentifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SignatureProductionPlace;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SigningCertificate;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SigningTime;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.ArchiveTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CertificateValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CompleteCertificateRefs;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CompleteRevocationRefs;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.RevocationValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.SigAndRefsTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.SignatureTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.creator.ArchiveTimeStampCreator;
import br.ufsc.labsec.signature.conformanceVerifier.xades.creator.CertificateValuesCreator;
import br.ufsc.labsec.signature.conformanceVerifier.xades.creator.CompleteCertificateRefsCreator;
import br.ufsc.labsec.signature.conformanceVerifier.xades.creator.CompleteRevocationRefsCreator;
import br.ufsc.labsec.signature.conformanceVerifier.xades.creator.Creator;
import br.ufsc.labsec.signature.conformanceVerifier.xades.creator.DataObjectFormatCreator;
import br.ufsc.labsec.signature.conformanceVerifier.xades.creator.RevocationValuesCreator;
import br.ufsc.labsec.signature.conformanceVerifier.xades.creator.SigAndRefsTimeStampCreator;
import br.ufsc.labsec.signature.conformanceVerifier.xades.creator.SignaturePolicyIdentifierCreator;
import br.ufsc.labsec.signature.conformanceVerifier.xades.creator.SignatureProductionPlaceCreator;
import br.ufsc.labsec.signature.conformanceVerifier.xades.creator.SignatureTimeStampCreator;
import br.ufsc.labsec.signature.conformanceVerifier.xades.creator.SigningCertificateCreator;
import br.ufsc.labsec.signature.conformanceVerifier.xades.creator.SigningTimeCreator;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 *  Esta classe mapeia o OID de um atributo para o seu nome e um atributo a seu respectivo Creator.
 */
public class AttributeFactory {

	/**
	 * Assinados XAdES
	 */
	private AbstractXadesSigner xadesSigner;
	/**
	 * Mapa que relaciona identificadores aos seus objetos {@link Creator}
	 */
	private HashMap<String, Creator> attributeFactoryMap;
	/**
	 * Conjunto de atributos assinados
	 */
	private Set<String> signedAttributes;
	/**
	 * Certificado do assinante
	 */
	private X509Certificate signerCertificate;

	/**
	 * Construtor
	 * @param signer um assinador XAdES
	 */
    public AttributeFactory(AbstractXadesSigner signer) {
    	this.xadesSigner = signer;
    	initializeAttributeFactoryMap();  	
    	
    	signedAttributes = new HashSet<>();
    	
    	signedAttributes.add(DataObjectFormat.IDENTIFIER);
    	signedAttributes.add(SigningTime.IDENTIFIER);
    	signedAttributes.add(SigningCertificate.IDENTIFIER);
    	signedAttributes.add(SignatureProductionPlace.IDENTIFIER);
    	signedAttributes.add(SignaturePolicyIdentifier.IDENTIFIER);
    	
    	
	}

	/**
	 * Inicializa o mapa que relaciona identificadores aos seus objetos {@link Creator}
	 */
	private void initializeAttributeFactoryMap() {
		this.attributeFactoryMap = new HashMap<String, Creator>();
		
		this.attributeFactoryMap.put(DataObjectFormat.IDENTIFIER, new DataObjectFormatCreator(xadesSigner));
		this.attributeFactoryMap.put(SigningTime.IDENTIFIER, new SigningTimeCreator(xadesSigner));
		this.attributeFactoryMap.put(SigningCertificate.IDENTIFIER, new SigningCertificateCreator(xadesSigner));
		this.attributeFactoryMap.put(SignaturePolicyIdentifier.IDENTIFIER, new SignaturePolicyIdentifierCreator(xadesSigner));
		this.attributeFactoryMap.put(SignatureProductionPlace.IDENTIFIER, new SignatureProductionPlaceCreator(xadesSigner));
		
		//Não assinados
		this.attributeFactoryMap.put(CompleteCertificateRefs.IDENTIFIER, new CompleteCertificateRefsCreator(xadesSigner));
		this.attributeFactoryMap.put(CompleteRevocationRefs.IDENTIFIER, new CompleteRevocationRefsCreator(xadesSigner));
		this.attributeFactoryMap.put(CertificateValues.IDENTIFIER, new CertificateValuesCreator(xadesSigner));
		this.attributeFactoryMap.put(RevocationValues.IDENTIFIER, new RevocationValuesCreator(xadesSigner));
//		this.attributeFactoryMap.put(SignerRole.IDENTIFIER, new AttributeCertificateRefsCreator(xadesSigner));
//		this.attributeFactoryMap.put(AttributeCertificateRefs.IDENTIFIER, new AttributeCertificateRefsCreator(xadesSigner));
//		this.attributeFactoryMap.put(AttributeRevocationRefs.IDENTIFIER, new AttributeCertificateRefsCreator(xadesSigner));
		
		//TIMESTAMP
		this.attributeFactoryMap.put(SignatureTimeStamp.IDENTIFIER, new SignatureTimeStampCreator(xadesSigner));
		this.attributeFactoryMap.put(SigAndRefsTimeStamp.IDENTIFIER, new SigAndRefsTimeStampCreator(xadesSigner));
		this.attributeFactoryMap.put(ArchiveTimeStamp.IDENTIFIER, new ArchiveTimeStampCreator(xadesSigner));
		
	}

	/**
	 * Retorna um atributo
	 * @param attribute o identificador do atributo
	 * @return o atributo correspondente ao identificador ou nulo se não for encontrado
	 * @throws SignatureAttributeException exceção em caso de erro na busca pelo atributo
	 */
	public SignatureAttribute getAttribute(String attribute) throws SignatureAttributeException {
		if(attributeFactoryMap.containsKey(attribute)){
			return attributeFactoryMap.get(attribute).getAttribute();	
		}
		return null;
	}

	/**
	 * Verifica se o atributo é assinado
	 * @param attribute o identificador do atributo a ser verificado
	 * @return indica se o atributo é assinado
	 */
	public boolean isSigned(String attribute) {
		return signedAttributes.contains(attribute);
	}

	/**
	 * Atribue o certificado do assinante
	 * @param signerCertificate o certificado do assinante
	 */
	public void setSignerCertificate(X509Certificate signerCertificate) {
		this.signerCertificate = signerCertificate;
	}

	/**
	 * Retorna o certificado do assinante
	 * @return o certificado do assinante
	 */
	public X509Certificate getSignerCertificate() {
		return this.signerCertificate;
	}
    
	/*
	 * Não implementados 
	 * 
	 * CommitmentTypeIndication AllDataObjectTimeStamp
	 * IndividualDataObjectsTimeStamp RefsOnlyTimeStamp
	 * AttrAuthoritiesCertValues AttributeRevocationValues
	 * UnsignedDataObjectProperty
	 */

	/*
	 * 
	 * SignerRole ? TODO 
	 * AttributeCertificateRefs ? TODO
	 * AttributeRevocationRefs ? TODO
	 */
    	    		
}

