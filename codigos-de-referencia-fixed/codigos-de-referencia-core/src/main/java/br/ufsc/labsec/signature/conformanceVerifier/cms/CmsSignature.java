package br.ufsc.labsec.signature.conformanceVerifier.cms;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.CertificateCollection;
import br.ufsc.labsec.signature.CertificateValidation.ValidationResult;
import br.ufsc.labsec.signature.SystemTime;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignatureContainer;
import br.ufsc.labsec.signature.conformanceVerifier.cades.SignatureVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.AttributeMap;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.TimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdCounterSignature;
import br.ufsc.labsec.signature.conformanceVerifier.report.AttribReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.CertRevReq;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.RevReq.EnuRevReq;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.RuntimeOperatorException;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.security.cert.*;
import java.sql.Time;
import java.util.*;
import java.util.logging.Level;

/**
 * Esta classe representa uma assinatura CMS.
 */
public class CmsSignature {

	/**
	 * Contêiner de assinatura CMS
	 */
	private CmsSignatureContainer signatureContainer;
	/**
	 * Informações do assinante
	 */
	private SignerInformation signerInfo;
	/**
	 * Componente de assinatura CMS
	 */
	private CmsSignatureComponent cmsSignatureComponent;
	private boolean isCounterSignature = false;

	/**
	 * Construtor
	 * @param signatureContainer Contêiner de assinatura CMS
	 * @param signerInfo Informações do assinante
	 * @param cmsSignatureComponent Componente de assinatura CMS
	 */
	public CmsSignature(CmsSignatureContainer signatureContainer, SignerInformation signerInfo,
			CmsSignatureComponent cmsSignatureComponent) {
		this.signatureContainer = signatureContainer;
		this.signerInfo = signerInfo;
		this.cmsSignatureComponent = cmsSignatureComponent;
	}

	/**
	 * Cria uma contra assinatura CMS
	 * @param signatureContainer Contêiner de assinatura
	 * @param signerInformation Informação do assinante
	 * @param cmsSignatureComponent Componente de assinatura
	 * @return A contra-assinatura criada
	 */
	private CmsSignature createCmsCounterSignature(CmsSignatureContainer signatureContainer,
												   SignerInformation signerInformation,
												   CmsSignatureComponent cmsSignatureComponent) {
		CmsSignature cmsSignature = new CmsSignature(signatureContainer, signerInformation, cmsSignatureComponent);
		cmsSignature.isCounterSignature = true;
		return cmsSignature;
	}

	/**
	 * Retorna o nome do assinante
	 * @return O nome do assinante
	 */
	public String getSubjectName() {
		X509Certificate certificate = this.getSigningCertificate();
		if (certificate != null) {
			return certificate.getSubjectX500Principal().toString();
		}

		return "";
	}

	/**
	 * Retorna o certificado do assinante
	 * @return O certificado do assinante
	 */
	public X509Certificate getSigningCertificate() {

		Store store = this.signatureContainer.getCertificateStore();
		Selector selector = this.signerInfo.getSID();
		Collection matches = store.getMatches(selector);

		try {
			if (!matches.isEmpty()) {
				X509CertificateHolder t = (X509CertificateHolder) matches.iterator().next();
				return new JcaX509CertificateConverter().getCertificate(t);
			}
		} catch (CertificateException e) {
			Application.logger.log(Level.SEVERE, "Não foi possível obter o certificado do assinante.");
		}

		return null;
	}

	/**
	 * Valida as informações da assinatura
	 * @return O relatório da verificação
	 */
	public SignatureReport validate() {

		SignatureReport report = new SignatureReport();

		X509CertSelector selector = new X509CertSelector();
		selector.setSerialNumber(this.signerInfo.getSID().getSerialNumber());

		try {
			selector.setIssuer(this.signerInfo.getSID().getIssuer().getEncoded());
		} catch (IOException e) {
			Application.logger.log(Level.SEVERE, "Não foi possível decodificar o nome do assinante.", e);
		}

		X509Certificate signerCertificate = null;
		Iterator<CertificateCollection> it = this.cmsSignatureComponent.certificateCollection.iterator();

		do {
			signerCertificate = (X509Certificate) it.next().getCertificate(selector);
		} while (signerCertificate == null && it.hasNext());

		if (signerCertificate == null) {
			report.setSignerSubjectName("Assinante desconhecido");
		} else {
			report.setSignerSubjectName(signerCertificate.getSubjectX500Principal().toString());
			boolean validHash = this.validateSignatureIntegrity(signerCertificate, report);
			// Todos os certificados na validação dos atributos são obtidos pela construção do caminho
			// de certificados, que resultará no download do AIA se necessário.
			this.validateAttributes(report, validHash);
		}

		Set<TrustAnchor> trustAnchors = this.cmsSignatureComponent.trustAnchorInterface.getTrustAnchorSet();
		CertRevReq revocationReqs = new CertRevReq(EnuRevReq.EITHER_CHECK, EnuRevReq.EITHER_CHECK);
		Time timeReference = new Time(SystemTime.getSystemTime());

		ValidationResult certificateValidationResults = this.cmsSignatureComponent.certificatePathValidation
				.validate(signerCertificate, trustAnchors, revocationReqs, timeReference, report);

		report.verifyValidationResult(certificateValidationResults);
		report.setSchema(SignatureReport.SchemaState.VALID);

		return report;

	}

	/**
	 * Valida as informações de hash e cifra assimétrica da assinatura.
	 * Adiciona as informações no relatório passado por parâmetro
	 * @param certificate Certificado utilizado na assinatura
	 * @param report O relatório da verificação
	 * @return Indica se a assinatura é integra
	 */
	private boolean validateSignatureIntegrity(X509Certificate certificate,
											   SignatureReport report) {

		JcaSimpleSignerInfoVerifierBuilder builder = new JcaSimpleSignerInfoVerifierBuilder();
		boolean valid = false;

		try {
			valid = this.signerInfo.verify(builder.build(certificate));
			report.setHash(valid);
			report.setAsymmetricCipher(valid);
		} catch (CMSException | RuntimeOperatorException e) {
			Application.logger.log(Level.SEVERE, "Ocorreu um erro ao verificar a assinatura.", e.getMessage());
		} catch (OperatorCreationException e) {
			Application.logger.log(Level.SEVERE, "Não foi possível inicializar o verificador da assinatura.", e);
		}

		return valid;

	}

	/**
	 * Retorna a lista de atributos da assinatura
	 * @return A lista com os nomes dos atributos da assinatura
	 */
	public List<String> getAttributeList() {

		List<String> attributeOidList = new ArrayList<String>();

		this.addAttributesFromTableToList(this.signerInfo.getSignedAttributes(), attributeOidList);
		this.addAttributesFromTableToList(this.signerInfo.getUnsignedAttributes(), attributeOidList);

		return attributeOidList;

	}

	/**
	 * Adiciona o conteúdo de uma {@link AttributeTable} à uma lista
	 * @param attrTable A tabela com as informações
	 * @param attrList A lista a ser preenchida
	 */
	private void addAttributesFromTableToList(AttributeTable attrTable, List<String> attrList) {

		ASN1EncodableVector attrTableVector;

		if (attrTable != null) {
			attrTableVector = attrTable.toASN1EncodableVector();
			for (int i = 0; i < attrTableVector.size(); i++) {
				Attribute attr = (Attribute) attrTableVector.get(i);
				attrList.add(attr.getAttrType().getId());
			}
		}

	}

	/**
	 * Valida os atributos obrigatórios e opcionais da assinatura
	 * @param report O relatório da verificação
	 * @param validHash A validade do hash da assinatura
	 */
	private void validateAttributes(SignatureReport report, boolean validHash) {
		if (this.signerInfo.getSignedAttributes() != null) {
			this.validateMandatedAttributes(report, validHash);
			this.validateOptionalAttributes(report);
			validateCounterSignatures(report);
		}
	}

	/**
	 * Valida as contra assinaturas presentes.
	 * @param report O relatório da verificação
	 */
	private void validateCounterSignatures(SignatureReport report) {
		Iterator<SignerInformation> counterSigIt = signerInfo.getCounterSignatures().iterator();
		while (counterSigIt.hasNext()) {
			AttribReport ar = new AttribReport();

			SignerInformation counterSigInformation = counterSigIt.next();
			CmsSignature cmsSignature = createCmsCounterSignature(this.signatureContainer, counterSigInformation, cmsSignatureComponent);

			SignatureReport r = cmsSignature.validate();

			ar.setAttribName(AttributeMap.translateName(IdCounterSignature.IDENTIFIER));
			// Indeterminação de contra-assinaturas?
			ar.setError(!r.isValid());

			report.addAttribOptionalReport(ar);
			report.addCounterSignatureReport(r);
		}
	}

	/**
	 * Valida os atributos obrigatórios na assinatura
	 * @param report O relatório da verificação
	 * @param validHash A validade do hash da assinatura
	 */
	private void validateMandatedAttributes(SignatureReport report, boolean validHash) {
		boolean validAttributes = true;
		validAttributes &= this.validateContentType(report);
		validAttributes &= this.validateMessageDigest(report, validHash);
		report.setPresenceOfInvalidAttributes(!validAttributes);
	}

	/**
	 * Faz a validação dos atributos presentes na assinatura, exceto os obrigatórios (IdContentType e IdMessageDigest).
	 * Utiliza os métodos do verificador CAdES pra realizar a validação
	 * @param report O relatório da verificação
	 */
	private void validateOptionalAttributes(SignatureReport report) {
		try {
			/* Instancia um verificador CAdES para realizar a validação dos atributos */
			CadesSignatureContainer cadesContainer =
					new CadesSignatureContainer(this.signatureContainer.getCmsSignedData());
			CadesSignatureComponent cadesComponent = (CadesSignatureComponent)
					this.cmsSignatureComponent.getApplication()
					.getComponent(CadesSignatureComponent.class.getName());
			cadesComponent.signaturePolicyInterface.setDefaultPolicy();
			for (Certificate c : this.cmsSignatureComponent.getSignatureIdentityInformation().getCertificateList()) {
				cadesComponent.getSignatureIdentityInformation().addCertificates(
						Collections.singletonList((X509Certificate) c));
			}
			SignatureVerifier cadesVerifier = new SignatureVerifier(
					new CadesSignature(cadesContainer, this.signerInfo, cadesContainer),
					null,
					cadesComponent.signaturePolicyInterface);
			cadesVerifier.setComponent(cadesComponent);
			cadesVerifier.setTimeReference(new Time(SystemTime.getSystemTime()));

			/* Realiza a validação dos atributos */
			this.verifyTimeStamps(report, cadesVerifier);
			this.validateExtraAttributes(report, cadesVerifier);
		} catch (PbadException e) {
			Application.logger.log(Level.SEVERE,
					"Erro ao instanciar o verificador CAdES para a validação dos atributos da assinatura CMS", e);
		}
	}

	/**
	 * Faz a verificação dos carimbos de tempo presentes na assinatura
	 * @param report O relatório da verificação
	 * @param cadesVerifier Um verificador CAdES, usado para validar os atributos
	 */
	private void verifyTimeStamps(SignatureReport report, SignatureVerifier cadesVerifier) {
		List<TimeStamp> timeStamps;
		List<PbadException> warnings = new ArrayList<PbadException>();
		try {
			timeStamps = cadesVerifier.getOrderedTimeStamps();
			cadesVerifier.verifySignatureTimestamps(warnings, timeStamps, report);
		} catch (Throwable e) {
			Application.logger.log(Level.SEVERE, "Erro ao validar os carimbos do tempo", e);
		}
	}

	/**
	 * Valida os outros atributos na assinatura, exceto IdContentType, IdMessageDigest, IdCounterSignature
	 * e os carimbos de tempo
	 * @param report O relatório da verificação
	 * @param cadesVerifier Um verificador CAdES, usado para validar os atributos
	 * @see CmsSignature#validateCounterSignatures(SignatureReport) para a validação do atributo IdCounterSignature
	 * @see CmsSignature#validateMandatedAttributes(SignatureReport, boolean) para a validação dos atributos IdContentType e IdMessageDigest
	 * @see CmsSignature#verifyTimeStamps(SignatureReport, SignatureVerifier) para a verificação dos carimbos de tempo
	 */
	private void validateExtraAttributes(SignatureReport report, SignatureVerifier cadesVerifier) {
		List<String> mandatedAttributes = new ArrayList<>();
		mandatedAttributes.add(PKCSObjectIdentifiers.pkcs_9_at_contentType.getId());
		mandatedAttributes.add(PKCSObjectIdentifiers.pkcs_9_at_messageDigest.getId());
		List<String> signatureAttributeList = this.getAttributeList();
		List<String> attributesAlreadyVerified = cadesVerifier.getTimeStampPriorityList();
		// Contra assinaturas são validadas por `validateCounterSignatures()`
		attributesAlreadyVerified.add(IdCounterSignature.IDENTIFIER);

		cadesVerifier.verifyOnlyUnmandatedAttributes(signatureAttributeList,
				mandatedAttributes, attributesAlreadyVerified, report);
	}

	/**
	 * Valida o atributo ContentType
	 * @param report O relatório da verificação
	 * @return Indica se o atributo é válido
	 */
	private boolean validateContentType(SignatureReport report) {

		ASN1ObjectIdentifier oid = PKCSObjectIdentifiers.pkcs_9_at_contentType;
		Attribute contentType = this.signerInfo.getSignedAttributes().get(oid);
		AttribReport attribReport = new AttribReport();
		boolean isValid = false;

		if (contentType != null) {
			attribReport.setAttribName(AttributeMap.translateName(oid.getId()));
			report.addAttribRequiredReport(attribReport);
			isValid = (this.getSignerInfo().getContentType() ==
					contentType.getAttrValues().getObjectAt(0));
		} else if (isCounterSignature) {
			isValid = true;
		}

		attribReport.setError(!isValid);
		if (!isValid) {
			attribReport.setErrorMessage(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + oid);
		}
		return isValid;
	}

	/**
	 * Valida o atributo MessageDigest
	 * @param report O relatório da verificação
	 * @param valid A validade do hash da assinatura
	 * @return Indica se o atributo é válido
	 */
	private boolean validateMessageDigest(SignatureReport report, boolean valid) {

		ASN1ObjectIdentifier oid = PKCSObjectIdentifiers.pkcs_9_at_messageDigest;
		Attribute messageDigest = this.signerInfo.getSignedAttributes().get(oid);
		AttribReport attribReport = new AttribReport();

		if (messageDigest != null) {
			// at least check if attribute is not empty
			report.setMessageDigest(((DEROctetString)messageDigest.getAttrValues().getObjectAt(0)).getOctets());
			attribReport.setAttribName(AttributeMap.translateName(oid.getId()));
			attribReport.setError(!valid);
			if (!valid) {
				attribReport.setErrorMessage(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + oid + " - " + SignatureAttributeException.HASH_FAILURE);
			}
			report.addAttribRequiredReport(attribReport);
			return valid;
		}
		return false;
	}

	/**
	 * Retorna as informações do assinante
	 * @return As informações do assinante
	 */
	public SignerInformation getSignerInfo() {
		return this.signerInfo;
	}

}
