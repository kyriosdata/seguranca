package br.ufsc.labsec.signature.conformanceVerifier.report;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Level;

import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.CertificateValidation.ValidationResult;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignerRules.CertInfoReq;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.CertificationPathException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe representa o relatório de uma assinatura
 */
public class SignatureReport {

	private static final String SIGNER_ONLY = "Assinante apenas";
	private static final String FULL_PATH = "Caminho completo";
	private static final String NONE = "Nenhum certificado é necessário";
	private static final String HASH = "hash";
	private static final String FALSE = "False";
	private static final String TRUE = "True";
	private static final String UNKNOWN = "Unknown";

	/**
	 * Enumeração das formas de obter o certificado do assinante
	 */
	public enum Form {
		KeyInfo, SigningCertificate, KeyInfoSigningCertificate, Certificates, CertificatesSigningCertificate
	}

	/**
	 * Enumeração dos estados de validade do certificado.
	 */
	public enum CertValidity {
		Valid, Revoked, Expired, NotValidYet, Invalid, Unknown
	}

	/**
	 * Enumeração dos estados de validade de um esquema XML
	 */
	public enum SchemaState {
		VALID(TRUE), INDETERMINATE(UNKNOWN), INVALID(FALSE);

		private final String desc;

		SchemaState(String value) {
			desc = value;
		}

		@Override
		public String toString() {
			return this.desc;
		}
	}

	/**
	 * Enumeração dos estados de validade de uma assinatura
	 */
	public enum SignatureValidity {
		Valid("Aprovado"), Indeterminate("Indeterminada"), Invalid("Reprovado");

		private final String desc;

		SignatureValidity(String value) {
			desc = value;
		}

		@Override
		public String toString() {
			return this.desc;
		}
	}

	/**
	 * Conjunto da validação de certificados e CRLs
	 */
	protected Set<ValidationDataReport> validation;
	/**
	 * Lista de relatórios de carimbo de tempo
	 */
	protected List<TimeStampReport> stamps;
	/**
	 * Lista de contra assinaturas
	 */
	protected List<SignatureReport> counterSignatures;
	/**
	 * Lista de relatórios de atributos obrigatórios
	 */
	protected List<AttribReport> requiredAttrib;
	/**
	 * Lista de relatórios de atributos opcionais
	 */
	protected List<AttribReport> optionalAttrib;
	/**
	 * Lista de relatórios de atributos extra
	 */
	protected List<AttribReport> extraReports;
	/**
	 * Lista de validade de referências
	 */
	protected List<Boolean> references;
	/**
	 * Tipo da assinatura
	 */
	protected String signatureType;
	/**
	 * Nome do assinante
	 */
	protected String signerSubjectName;
	/**
	 * Regras obrigatórias
	 */
	protected String requiredRules;
	/**
	 * Regras proibidas
	 */
	protected String prohibitedRules;
	/**
	 * Lista de mensagens de erro da verificação
	 */
	private List<String> errorMessages;
	protected boolean present;
	/**
	 * Validade do esquema XML
	 */
	protected SchemaState schema;
	/**
	 * Valor do hash da assinatura
	 */
	protected byte[] messageDigest;
	/**
	 * Validade do hash da assinatura
	 */
	protected boolean hash;
	/**
	 * Validade da cifra assimétrica
	 */
	protected boolean asymmetricCipher;
	private Form form;
	/**
	 * Validade do caminho de certificação
	 */
	protected CertValidity certPathValidity;
	/**
	 * Mensagem do caminho de certificação
	 */
	protected String certPathMessage;
	/**
	 * Informação obrigatória de certificado
	 */
	private String mandatedCertificateInfo;
	/**
	 * Indica se há presença de todos os certificados necessários
	 */
	private boolean containsAllCertificatesNeeded;
	/**
	 * Mensagem do esquema XML
	 */
	private String schemaMessage;
	/**
	 * OID da política de assinatura
	 */
	private String signaturePolicy;
	/**
	 * Indica a presença de um atributo inválido
	 */
	protected boolean hasAttributeExceptions;
	/**
	 * Validade do OID da política de assinatura
	 */
	private boolean paOidValid;
	/**
	 * Indica a presença de atualizações incrementais inválidas
	 */
	private boolean hasInvalidUpdates;
	/**
	 * Indica indeterminação por atualizações incrementais
	 */
	private boolean hasPossibleInvalidUpdates;
	/**
	 * Indica a presença de um carimbo de tempo válido
	 */
	protected boolean hasOneValidTimeStamp;
	/**
	 * Indica a presença de um carimbo de tempo inválido
	 */
	protected boolean hasOneInvalidTimeStamp;
	/**
	 * Indica a presença de um carimbo de tempo expirado
	 */
	protected boolean hasOneExpiredTimeStamp;
	/**
	 * Indica a presença de apenas carimbos de tempo expirados
	 */
	protected boolean hasOnlyExpiredTimeStamps;

	/**
	 * Construtor da classe
	 */
	public SignatureReport() {
		this.validation = new LinkedHashSet<ValidationDataReport>();
		this.stamps = new ArrayList<TimeStampReport>();
		this.counterSignatures = new ArrayList<SignatureReport>();
		this.references = new ArrayList<Boolean>();
		this.optionalAttrib = new ArrayList<AttribReport>();
		this.requiredAttrib = new ArrayList<AttribReport>();
		this.optionalAttrib = new ArrayList<AttribReport>();
		this.extraReports = new ArrayList<AttribReport>();
		this.references = new ArrayList<Boolean>();
		this.errorMessages = new ArrayList<String>();
		paOidValid = true;
		hasInvalidUpdates = false;
		hasPossibleInvalidUpdates = false;
		hasOneValidTimeStamp = false;
		hasOneExpiredTimeStamp = false;
		hasOneInvalidTimeStamp = false;
	}

	/**
	 * Atribue o tipo da assinatura
	 *
	 * @param signatureType O tipo da assinatura
	 */
	public void setSignatureType(String signatureType) {
		this.signatureType = signatureType;
	}

	/**
	 * Atribue as regras obrigatórias
	 *
	 * @param required As regras obrigatórias
	 */
	public void setRequiredRules(String required) {
		this.requiredRules = required;
	}

	/**
	 * Atribue as regras proibidas
	 *
	 * @param prohibited As regras proibidas
	 */
	public void setProhibitedRules(String prohibited) {
		this.prohibitedRules = prohibited;
	}

	/**
	 * Atribue uma mensagem de erro
	 * @param errorMessages A mensagem de erro
	 */
	public void setErrorMessage(String errorMessages) {
		this.errorMessages.add(errorMessages);
	}
	/**
	 * Atribue se está presente
	 *
	 * @param present Se está presente
	 */
	public void setPresent(boolean present) {
		this.present = present;
	}

	/**
	 * Atribue form
	 *
	 * @param form
	 *            Form
	 */
	public void setForm(Form form) {
		this.form = form;
	}

	/**
	 * Atribue a validade do esquema
	 *
	 * @param schema A validade do esquema
	 */
	public void setSchema(SchemaState schema) {
		this.schema = schema;
	}

	/**
	 * Atribue a validade do hash
	 *
	 * @param hash A validade do hash
	 */
	public void setHash(boolean hash) {
		this.hash = hash;
	}

	// public void setXmlHash(boolean xmlHash){
	// this.xmlHash = xmlHash;
	// }

	/**
	 * Atribue a validade da cifra assimétrica
	 *
	 * @param asymmetricCipher A validade da cifra assimétrica
	 */
	public void setAsymmetricCipher(boolean asymmetricCipher) {
		this.asymmetricCipher = asymmetricCipher;
	}

	/**
	 * Atribue o nome do assinante
	 *
	 * @param name O nome do assinante
	 */
	public void setSignerSubjectName(String name) {
		this.signerSubjectName = name;
	}

	/**
	 * Atribue a validade do OID da PA
	 * @param valid A validade do OID da PA
	 */
	public void setPaOidValid(boolean valid) {
		this.paOidValid = valid;
	}

	/**
	 * Atribue invalidação por atualização incrementais
	 */
	public void invalidateDueToIncrementalUpdates() {
		this.hasInvalidUpdates = true;
	}

	/**
	 * Atribue indeterminação por atualizações incrementais
	 */
	public void indeterminateDueToPossibleIncrementalUpdate() {
		this.hasPossibleInvalidUpdates = true;
	}

	/**
	 * Retorna se a assinatura é inválida pela validação de atualizações incrementais
	 * @return Se há atualizações incrementais inválidas
	 */
	public boolean isInvalidDueToIncrementalUpdates() {
		return hasInvalidUpdates;
	}

	/**
	 * Retorna se a assinatura é indeterminada pela validação de atualizações incrementais
	 * @return Se há atualizações incrementais inválidas
	 */
	public boolean isIndeterminateDueToIncrementalUpdates() {
		return hasPossibleInvalidUpdates;
	}
	/**
	 * Adiciona um relatório de validação de CRLs e certificados
	 * @param validationData O relatório de validação de CRLs e certificados
	 */
	public void addValidation(ValidationDataReport validationData) {
		this.validation.add(validationData);
	}

	/**
	 * Adiciona um relatório de carimbo de tempo
	 *
	 * @param timeStampReport O relatório de carimbo de tempo a ser adicionado
	 */
	public void addTimeStampReport(TimeStampReport timeStampReport) {
		this.stamps.add(timeStampReport);
	}

	/**
	 * Adiciona relatórios de verificação de contra-assinaturas recursivamente
	 * @param counterSignatureReport O relatório com as contra-assinaturas
	 */
	public void addCounterSignatureReport(SignatureReport counterSignatureReport) {
		this.counterSignatures.add(counterSignatureReport);
		for (int i = 0; i < counterSignatureReport.counterSignatures.size(); i++) {
			this.addCounterSignatureReport(counterSignatureReport.counterSignatures.get(i));
		}
		counterSignatureReport.counterSignatures = new ArrayList<>();
	}

	/**
	 * Adiciona um relatório de atributo opcional
	 * @param attrib O relatório de atributo a ser adicionado
	 */
	public void addAttribOptionalReport(AttribReport attrib) {
		this.optionalAttrib.add(attrib);
	}

	/**
	 * Adiciona um relatório de atributo obrigatório
	 *
	 * @param attrib O relatório de atributo a ser adicionado
	 */
	public void addAttribRequiredReport(AttribReport attrib) {
		this.requiredAttrib.add(attrib);
	}

	/**
	 * Adiciona a validade de uma referência
	 *
	 * @param bool A validade de uma referência
	 */
	public void addReferences(boolean bool) {
		this.references.add(bool);
	}

	/**
	 * Adiciona um relatório de atributo extra
	 *
	 * @param attribReport O relatório de atributo a ser adicionado
	 */
	public void addExtraAttrReport(AttribReport attribReport){
		this.extraReports.add(attribReport);
	}

	/**
	 * Gera elemento da assinatura
	 *
	 * @param document
	 *            Document
	 * @return {@link Element}
	 * @throws SignatureAttributeException
	 *             erro ao gerar documento do timeStamp
	 */
	public Element generateSignatureElement(Document document) throws SignatureAttributeException {

		Element signature = document.createElement("signature");

		Element signatureType = document.createElement("signatureType");
		signature.appendChild(signatureType);
		signatureType.setTextContent(this.signatureType);

		Element containsMandatedCertificates = document.createElement("containsMandatedCertificates");
		signature.appendChild(containsMandatedCertificates);
		containsMandatedCertificates.setTextContent(this.containsAllCertificatesNeeded ? TRUE : FALSE);

		Element hasInvalidUpdates = document.createElement("hasInvalidUpdates");
		signature.appendChild(hasInvalidUpdates);
		hasInvalidUpdates.setTextContent(this.hasInvalidUpdates ? TRUE : FALSE);

		Element paRules = document.createElement("paRules");
		signature.appendChild(paRules);

		Element required = document.createElement("required");
		paRules.appendChild(required);
		required.setTextContent(this.requiredRules);

		Element prohibited = document.createElement("prohibited");
		paRules.appendChild(prohibited);
		prohibited.setTextContent(this.prohibitedRules);

		Element errorMessages = document.createElement("errorMessages");
		for (int i = 0; i < this.errorMessages.size(); i++) {
			Element errorMessage = document.createElement("errorMessage");
			errorMessage.setTextContent(this.errorMessages.get(i));
			errorMessages.appendChild(errorMessage);
		}
		signature.appendChild(errorMessages);

		Element mandatedCertificateInfo = document.createElement("mandatedCertificateInfo");
		mandatedCertificateInfo.setTextContent(this.mandatedCertificateInfo);
		paRules.appendChild(mandatedCertificateInfo);

		Element certification = document.createElement("certification");
		signature.appendChild(certification);

		Element signaturePolicy = document.createElement("signaturePolicy");
		signature.appendChild(signaturePolicy);
		signaturePolicy.setTextContent(this.signaturePolicy);

		Element signer = document.createElement("signer");
		Element signerSubjectName = document.createElement("subjectName");
		signerSubjectName.setTextContent(this.signerSubjectName);
		signer.appendChild(signerSubjectName);

		Element certPathElement = document.createElement("certPathValid");
		certPathElement.setTextContent(this.certPathValidity.toString());
		signer.appendChild(certPathElement);

		if (this.certPathValidity != CertValidity.Valid) {
			Element certPathMessageElement = document.createElement("certPathMessage");
			certPathMessageElement.setTextContent(this.certPathMessage);
			signer.appendChild(certPathMessageElement);
		}
		certification.appendChild(signer);

		Element present = document.createElement("present");
		signer.appendChild(present);
		if (this.present)
			present.setTextContent(TRUE);
		else
			present.setTextContent(FALSE);

		Element validSignature = document.createElement("validSignature");
		signer.appendChild(validSignature);
		validSignature.setTextContent(this.validityStatus().toString());

		if (this.form != null) {
			Element form = document.createElement("form");
			signer.appendChild(form);
			form.setTextContent(this.form.toString());
		}

		this.generateFormElement(document, signer);
		this.generateTimeStampsElement(document, certification);
		this.generateCounterSignatureElement(document, signature);

		return generateAttribElement(document, signature, certification);

	}

	/**
	 * Gera elemento da classe Form
	 *
	 * @param document
	 *            Document
	 * @param signer
	 *            Element
	 */
	private void generateFormElement(Document document, Element signer) {

		for (ValidationDataReport certReport : this.validation) {
			Element cert = certReport.generateCertificateElement(document);
			if (cert != null) {
				for (ValidationDataReport lcrReport : this.validation) {
					String issuerName = lcrReport.getCrlIssuerName();
					if (issuerName != null) {
						Boolean equalNames = issuerName.replaceAll("\\s", "").equals(
								certReport.getCertificateSubjectName().replaceAll("\\s", "")); // removes whitespaces
						if (equalNames) {
							Element crl = lcrReport.generateCrlElement(document);
							if (crl != null) {
								cert.appendChild(crl);
								break;
							}
						}
					}
				}
				signer.appendChild(cert);
			}
		}
		this.completeFormElement(document, signer);
	}

	/**
	 * Completa o elemento da classe Form
	 *
	 * @param document
	 *            Document
	 * @param signer
	 *            Element
	 */
	private void completeFormElement(Document document, Element signer) {

//		for (ValidationDataReport crlReport : this.validation) {
//			if (!crlReport.hasCrl()) {
//				Element crl = crlReport.generateCrlElement(document);
//				if (crl != null) {
//					signer.appendChild(crl);
//				}
//			}
//		}

		for (ValidationDataReport ocspReport : this.validation) {
			if (!ocspReport.hasOcsp()) {
				Element ocsp = ocspReport.generateOcspElement(document);
				if (ocsp != null) {
					signer.appendChild(ocsp);
				}
			}
		}

	}

	/**
	 * Gera o elemento do carimbo do tempo
	 *
	 * @param document
	 *            Document
	 * @param certification
	 *            Element
	 */
	private void generateTimeStampsElement(Document document, Element certification) {
		Element timeStamps = document.createElement("timeStamps");
		certification.appendChild(timeStamps);

		for (TimeStampReport timeStamp : this.stamps) {
			try {
				timeStamps.appendChild(timeStamp.generate(document));
			} catch (DOMException e) {
				Application.logger.log(Level.SEVERE, "Erro ao gerar documento", e);
			} catch (SignatureAttributeException e) {
				Application.logger.log(Level.SEVERE, "Erro ao gerar elemento de assinatura", e);
			}
		}
	}

	private void generateCounterSignatureElement(Document document, Element reportElement) throws SignatureAttributeException {
		if (!this.counterSignatures.isEmpty()) {
			Element counterSignatures = document.createElement("counterSignatures");
			for (SignatureReport report : this.counterSignatures) {
				counterSignatures.appendChild(report.generateSignatureElement(document));
			}
			reportElement.appendChild(counterSignatures);
		}
	}

	/**
	 * Gera itens de atributo
	 *
	 * @param document
	 *            Document
	 * @param signature
	 *            Element
	 * @param certification
	 *            Element
	 * @return {@link Element}
	 */
	private Element generateAttribElement(Document document, Element signature, Element certification) {

		Element attributes = document.createElement("attributes");
		signature.appendChild(attributes);

		Element requiredAttributes = document.createElement("requiredAttributes");
		attributes.appendChild(requiredAttributes);

		for (AttribReport attrib : this.requiredAttrib) {
			requiredAttributes.appendChild(createAttrElemente("requiredAttribute", document, attrib));
		}

		Element optionalAttributes = document.createElement("optionalAttributes");
		attributes.appendChild(optionalAttributes);

		for (AttribReport attrib : this.optionalAttrib) {
			optionalAttributes.appendChild(createAttrElemente("optionalAttribute", document, attrib));
		}

		Element extraAttributes = document.createElement("extraAttributes");
		attributes.appendChild(extraAttributes);

		for (AttribReport attrib : this.extraReports) {
			extraAttributes.appendChild(createAttrElemente("extraAttribute", document, attrib));
		}

		return generateSchemaElement(document, signature);

	}

	private Element createAttrElemente(String name, Document document, AttribReport attrib) {
		Element attribute = document.createElement(name);
		attribute.appendChild(attrib.generateNameElement(document));
		attribute.appendChild(attrib.generateErrorElement(document));
		if (attrib.hasError()) {
			attribute.appendChild(attrib.generateErrorMessageElement(document));
		}
		if(attrib.hasWarning())
			attribute.appendChild(attrib.generateAlertMessageElement(document));

		return attribute;
	}

	/**
	 * Gera elementos de esquema e hash
	 *
	 * @param document
	 *            Document
	 * @param signature
	 *            Element
	 * @return {@link Element}
	 */
	private Element generateSchemaElement(Document document, Element signature) {

		Element integrity = document.createElement("integrity");
		signature.appendChild(integrity);
		Element schema = document.createElement("schema");
		integrity.appendChild(schema);

		schema.setTextContent(this.schema.toString());
		if (!isSchema()) {
			Element schemaMessage = document.createElement("schemaMessage");
			schemaMessage.setTextContent(this.schemaMessage);
			integrity.appendChild(schemaMessage);
		}

		if (this.references != null) {
			Element references = document.createElement("references");
			integrity.appendChild(references);

			for (Boolean referenceValue : this.references) {
				Element reference = document.createElement("reference");
				references.appendChild(reference);

				Element xmlHash = document.createElement(HASH);
				reference.appendChild(xmlHash);
				if (referenceValue)
					xmlHash.setTextContent(TRUE);
				else
					xmlHash.setTextContent(FALSE);
			}

		}

		 integrity = generateHashElement(document, integrity, signature);

		return generateAttributeValidElement(document,integrity,signature);
	}

	private Element generateAttributeValidElement(Document document,
			Element integrity, Element signature) {
		Element attributeValid = document.createElement("attributeValid");
		integrity.appendChild(attributeValid);
		if (this.hasAttributeExceptions)
			attributeValid.setTextContent(FALSE);
		else
			attributeValid.setTextContent(TRUE);
		return signature;
	}

	/**
	 * Gera elemento do hash e concluir elemento da assinatura
	 *
	 * @param document
	 *            Document
	 * @param integrity
	 *            Element
	 * @param signature
	 *            Element
	 * @return {@link Element}
	 */
	private Element generateHashElement(Document document, Element integrity, Element signature) {
		Element hash = document.createElement(HASH);
		integrity.appendChild(hash);
		if (this.hash)
			hash.setTextContent(TRUE);
		else
			hash.setTextContent(FALSE);

		Element messageDigest = document.createElement("messageDigest");
		messageDigest.setTextContent(this.getMessageDigest());
		integrity.appendChild(messageDigest);

		Element asymmetricCipher = document.createElement("asymmetricCipher");
		integrity.appendChild(asymmetricCipher);
		if (this.asymmetricCipher & this.hash)
			asymmetricCipher.setTextContent(TRUE);
		else
			asymmetricCipher.setTextContent(FALSE);

		return signature;
	}

	/**
	 * Atribue a validade do caminho de certificação
	 * @param valid A validade do caminho de certificação
	 */
	public void setCertificationPathValid(CertValidity valid) {
		this.certPathValidity = valid;
	}

	/**
	 * Atribue a mensagem do caminho de certificação
	 * @param message A mensagem do caminho de certificação
	 */
	public void setCertificationPathMessage(String message) {
		this.certPathMessage = message;
	}

	/**
	 * Atualiza a validade e a mensagem do caminho de certificação de acordo com
	 * o resultado da validação do certificado.
	 * @param validationResult O resultado da validação do certificado
	 */
	public void verifyValidationResult(ValidationResult validationResult) {

		if (validationResult == ValidationResult.valid) {
			this.setCertificationPathValid(CertValidity.Valid);
		} else {
			String errorMessage = validationResult.getMessage();

			switch (errorMessage) {
				case CertificationPathException.CERTIFICATE_NOT_VALID_YET:
					this.setCertificationPathValid(CertValidity.NotValidYet);
					break;
				case CertificationPathException.EXPIRED_CERTIFICATE:
					this.setCertificationPathValid(CertValidity.Expired);
					break;
				case CertificationPathException.REVOKED_CERTIFICATE:
					this.setCertificationPathValid(CertValidity.Revoked);
					this.setRevokedCertificate(validationResult.getRevocationCertificate());
					break;
				case CertificationPathException.CRL_NOT_FOUND:
				case CertificationPathException.UNSPECIFIED:
					this.setCertificationPathValid(CertValidity.Unknown);
					break;
				default:
					this.setCertificationPathValid(CertValidity.Invalid);
					break;
			}

			this.setCertificationPathMessage(validationResult.getMessage());
		}

	}

	/**
	 * Atribue o estado de revogado ao certificado
	 * @param revocationCertificate O certificado revogado
	 */
	private void setRevokedCertificate(Certificate revocationCertificate) {
		Set<ValidationDataReport> validationDataReports = this.getValidation();
		X509Certificate x509revocationCertificate = (X509Certificate) revocationCertificate;
		String issuerName = x509revocationCertificate.getIssuerX500Principal().toString();
		BigInteger sn = x509revocationCertificate.getSerialNumber();
		String serialNumber = sn.toString();

		for (ValidationDataReport vdr : validationDataReports) {
			if(issuerName.equals(vdr.getCertificateIssuerName()) &&
					serialNumber.equals(vdr.getCertificateSerialNumber())){
				vdr.setRevoked(true);
			}
		}
	}

	/**
	 * Atribue o valor do atributo mandatedCertificateInfo de acordo com o parâmetro
	 * @param mandatedCertificateInfo O valor da informação obrigatória de certificado
	 */
	public void setCertificatesRequiredOnSignature(CertInfoReq mandatedCertificateInfo) {
		if (mandatedCertificateInfo == null) {
			this.mandatedCertificateInfo = NONE;
		} else {
			switch (mandatedCertificateInfo) {
			case SIGNER_ONLY:
				this.mandatedCertificateInfo = SIGNER_ONLY;
				break;
			case FULL_PATH:
				this.mandatedCertificateInfo = FULL_PATH;
				break;
			case NONE:
				this.mandatedCertificateInfo = NONE;
				break;
			default:
				this.mandatedCertificateInfo = NONE;
			}
		}
	}

	/**
	 * Atribue a presença de todos os certificados necessários
	 * @param contains Presença de todos os certificados necessários
	 */
	public void setContainsMandatedCertificates(boolean contains) {
		this.containsAllCertificatesNeeded = contains;
	}

	/**
	 * Atribue a mensagem do esquema
	 * @param message A mensagem do esquema
	 */
	public void setSchemaMessage(String message) {
		this.schemaMessage = message;
	}

	/**
	 * Retorna o conjunto de relatórios de validação de certificados e CRLs
	 * @return O conjunto de validações de certificados e CRLs
	 */
	public Set<ValidationDataReport> getValidation() {
		return validation;
	}

	/**
	 * Retorna a lista de carimbos de tempo
	 * @return A lista de carimbos de tempo
	 */
	public List<TimeStampReport> getStamps() {
		return stamps;
	}

	/**
	 * Retorna a lista de atributos obrigatórios
	 * @return A lista de atributos obrigatórios
	 */
	public List<AttribReport> getRequiredAttrib() {
		return requiredAttrib;
	}

	/**
	 * Retorna a lista de atributos opcionais
	 * @return A lista de atributos opcionais
	 */
	public List<AttribReport> getOptionalAttrib() {
		return optionalAttrib;
	}

	/**
	 * Retorna a lista de referências
	 * @return A lista de referências
	 */
	public List<Boolean> getReferences() {
		return references;
	}

	/**
	 * Retorna o tipo da assinatura
	 * @return O tipo da assinatura
	 */
	public String getSignatureType() {
		return signatureType;
	}

	/**
	 * Retorna o nome do assinante
	 * @return O nome do assinante
	 */
	public String getSignerSubjectName() {
		return signerSubjectName;
	}

	/**
	 * Retorna as regras obrigatórias
	 * @return As regras obrigatórias
	 */
	public String getRequiredRules() {
		return requiredRules;
	}

	/**
	 * Retorna as regras proibidas
	 * @return As regras proibidas
	 */
	public String getProhibitedRules() {
		return prohibitedRules;
	}

	/**
	 * Retorna a lista de mensagens de erro
	 * @return A lista de mensagens de erro
	 */
	public List<String> getErrorMessages() {
		return errorMessages;
	}

	/**
	 * Retorna se está presente
	 * @return Indica se está presente
	 */
	public boolean isPresent() {
		return present;
	}

	/**
	 * Retorna a validade do esquema
	 * @return Indica se o esquema é válido
	 */
	public boolean isSchema() {
		return schema == SchemaState.VALID;
	}

	/**
	 * Retorna a validade do hash
	 * @return Indica se o hash é válido
	 */
	public boolean isHash() {
		return hash;
	}

	/**
	 * Retorna se a assinatura é válida
	 * @return Indica se a assinatura é válida
	 */
	public boolean isValid() {
		return isNonRepudiable() && isHash() && isCertPathValid() && !hasAttributeExceptions && isPaOidValid() &&
				!hasInvalidUpdates && !hasPossibleInvalidUpdates;
	}

	/**
	 * Retorna se a assinatura é inválida por conter carimbos de tempo expirados
	 * @return Indica se a assinatura é inválida
	 */
	private boolean isInvalidByExpiredTimeStamps() {
		boolean invalidAttributes = isNonRepudiable() && isHash() && isCertPathValid() && isPaOidValid() &&
				!hasInvalidUpdates && !hasPossibleInvalidUpdates;
		if (!isValid() && invalidAttributes) { // signature is invalid because of invalid attributes
			for (AttribReport att : this.requiredAttrib) {
				if (att.hasError() && !att.getAttribName().toLowerCase().contains("time")) {
					return false; // invalid attributes are not only time stamps
				}
			}
			return !this.stamps.isEmpty() && hasOneExpiredTimeStamp && !hasOneInvalidTimeStamp;
		}
		return false; // invalid hash, cert path, etc
	}

	/**
	 * Retorna a validade da assinatura
	 * @return Indica a validade da assinatura
	 */
	public SignatureValidity validityStatus() {
		if (!isValid()) {
			boolean signatureInvalid = !this.isNonRepudiable() || !this.isHash() || !((this.stamps.isEmpty() && !this.hasAttributeExceptions) || !this.isPaOidValid());
			boolean incrementalUpdatesInvalid = this.hasInvalidUpdates;
			if ((!signatureInvalid && !incrementalUpdatesInvalid) || this.isInvalidByExpiredTimeStamps()) {
				return SignatureValidity.Indeterminate;
			} else {
				return SignatureValidity.Invalid;
			}
		}
		return SignatureValidity.Valid;
	}

	/**
	 * Retorna a validade da cifra assimétrica
	 * @return A validade da cifra assimétrica
	 */
	public boolean isNonRepudiable() {
		return this.asymmetricCipher;
	}

	/**
	 * Retorna a forma de obter o certificado do assinante
	 * @return A forma de obter o certificado do assinante
	 */
	public Form getForm() {
		return form;
	}

	/**
	 * Retorna se o caminho de certificação é válido
	 * @return Indica se o caminho de certificação é válido
	 */
	public boolean isCertPathValid() {
		return this.certPathValidity == CertValidity.Valid;
	}

	/**
	 * Retorna a presença de atributos com exceções
	 * @return Indica a presença de atributos inválidos
	 */
	public boolean isHasAttributeExceptions() {return this.hasAttributeExceptions;}

	/**
	 * Retorna a validade do caminho de certificação
	 * @return A validade do caminho de certificação
	 */
	public String getCertPathState() {
		return this.certPathValidity.toString();
	}

	/**
	 * Retorna a mensagem do caminho de certificação
	 * @return A mensagem do caminho de certificação
	 */
	public String getCertPathMessage() {
		return certPathMessage;
	}

	/**
	 * Retorna a informação obrigatória de certificado
	 * @return A informação obrigatória de certificado
	 */
	public String getMandatedCertificateInfo() {
		return mandatedCertificateInfo;
	}

	/**
	 * Retorna se todos os certificados necessários estão presentes
	 * @return Indica a presença de todos os certificados necessários
	 */
	public boolean isContainsAllCertificatesNeeded() {
		return containsAllCertificatesNeeded;
	}

	/**
	 * Retorna a mensagem do esquema
	 * @return A mensagem do esquema
	 */
	public String getSchemaMessage() {
		return schemaMessage;
	}

	/**
	 * Retorna a política de assinatura
	 * @return A política de assinatura
	 */
	public String getSignaturePolicy() {
		return signaturePolicy;
	}

	/**
	 * Atribue a política de assinatura
	 * @param signaturePolicy A política de assinatura
	 */
	public void setSignaturePolicy(String signaturePolicy) {
		this.signaturePolicy = signaturePolicy;
	}

	/**
	 * Atribue a presença de atributos inválidos
	 * @param hasAttributeExceptions A presença de atributos inválidos
	 */
	public void setPresenceOfInvalidAttributes(boolean hasAttributeExceptions) {
		this.hasAttributeExceptions = hasAttributeExceptions;
	}

	/**
	 * Retorna se o OID da política de assinatura é válido
	 * @return Indica se o OID da política de assinatura é válido
	 */
	public boolean isPaOidValid() {
		return paOidValid;
	}

	/**
	 * Retorna o valor do hash da assinatura
	 * @return O hash da assinatura
	 */
	public String getMessageDigest() {
		if (this.messageDigest == null ) { return ""; }
		return Hex.toHexString(this.messageDigest);
	}

	/**
	 * Atribue o valor do hash da assinatura
	 * @param messageDigest O hash da assinatura
	 */
	public void setMessageDigest(byte[] messageDigest) {
		this.messageDigest = messageDigest;
	}

	/**
	 * Atribue a presença de um carimbo de tempo válido
	 * @param hasOneValidTimeStamp A presença de um carimbo de tempo válido
	 */
	public void setHasOneValidTimeStamp(boolean hasOneValidTimeStamp) {
		this.hasOneValidTimeStamp = hasOneValidTimeStamp;
	}

	/**
	 * Atribue a presença de um carimbo de tempo expirado
	 * @param hasOneExpiredTimeStamp A presença de um carimbo de tempo expirado
	 */
	public void setHasOneExpiredTimeStamp(boolean hasOneExpiredTimeStamp) {
		this.hasOneExpiredTimeStamp = hasOneExpiredTimeStamp;
	}

	/**
	 * Atribue a presença de um carimbo de tempo inválido
	 * @param hasOneInvalidTimeStamp A presença de um carimbo de tempo inválido
	 */
	public void setHasOneInvalidTimeStamp(boolean hasOneInvalidTimeStamp) {
		this.hasOneInvalidTimeStamp = hasOneInvalidTimeStamp;
	}

	/**
	 * Insere informações da assinatura no log
	 */
	public void log() {

		String sigSch = isSchema() ? "" : "não ";
		Application.loggerInfo.log(Level.INFO, "Assinatura " + sigSch
				+ "está de acordo com o schema. " + Objects.toString(this.schemaMessage, ""));

		String sigPath = (this.certPathValidity == CertValidity.Valid) ? "" : "in";
		Application.loggerInfo.log(Level.INFO, "Caminho de certificação " + sigPath + "válido. "
				+ Objects.toString(this.certPathMessage, ""));

		String sigHash = this.hash ? "" : "in";
		Application.loggerInfo.log(Level.INFO, "Resumo criptográfico " + sigHash + "válido.");

		Application.loggerInfo.log(Level.INFO, "Status da assinatura é "
				+ this.validityStatus().toString().toLowerCase() + ".");

		for (AttribReport ar : this.requiredAttrib) {
			ar.log("obrigatório");
		}

		for (AttribReport ar : this.optionalAttrib) {
			ar.log("opcional");
		}

		if (this.stamps.size() > 0) {
			Application.loggerInfo.log(Level.INFO, "Carimbos do tempo: ");
			for (TimeStampReport tr : this.stamps) {
				tr.log();
			}
		}

	}

}
