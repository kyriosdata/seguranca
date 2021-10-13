/*

oDesenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades;

import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.*;
import java.util.logging.Level;

import br.ufsc.labsec.signature.SystemTime;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.TimeStampException;
import br.ufsc.labsec.signature.exceptions.*;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.CertificateValidation.ValidationResult;
import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.SignaturePolicyInterface.AdESType;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.AttributeMap;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.TimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaSignatureTimeStampToken;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.CertificationPathException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.CertificationPolicyException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureConformityException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureVerifierException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignerCertificationPathException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.UnknowAttributeException;
import br.ufsc.labsec.signature.conformanceVerifier.report.AttribReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.PaReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport.Form;
import br.ufsc.labsec.signature.conformanceVerifier.report.TimeStampReport;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.SignaturePolicyComponent;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignaturePolicy;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignerRules.CertInfoReq;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignerRules.ExternalSignedData;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SigningPeriod;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.exceptions.LpaException;

/**
 * Esta classe é responsável por verificar uma assinatura.
 * Estende {@link AbstractVerifier}.
 */
public class SignatureVerifier extends AbstractVerifier {

	/**
	 * A política de assinatura
	 */
	protected SignaturePolicyInterface signaturePolicy;
	/**
	 * O conteúdo assinado
	 */
	protected byte[] bytesOfSignedContent;

	/**
	 * Constrói um {@link SignatureVerifier} a partir da assinatura a ser
	 * verificada e da política de assinatura usada na assinatura.
	 * @param signature A assinatura a ser verificada
	 * @param cadesSignatureComponent Componente de assinatura CAdES
	 * @throws PbadException Exceção em caso de erro na inicialização da classe
	 */
	public SignatureVerifier(CadesSignature signature, CadesSignatureComponent cadesSignatureComponent)
			throws PbadException {
		signaturePolicy = cadesSignatureComponent.signaturePolicyInterface;
		this.component = cadesSignatureComponent;
		if (cadesSignatureComponent.getVerifier().getPolicyType() == null) {
			try {
				signaturePolicy.setActualPolicy(signature.getSignaturePolicyIdentifier(), signature.getSignaturePolicyUri(),
						AdESType.CAdES);
			} catch (Exception e) {
				signaturePolicy.setDefaultPolicy();
			}
		}
		initialize(signature, null);
	}

	/**
	 * Constrói um {@link SignatureVerifier} a partir da assinatura a ser
	 * verificada.
	 * @param signature A assinatura a ser verificada
	 * @param signaturePolicyComponent Componente de política de assinatura
	 * @throws SignatureVerifierException
	 * @throws PbadException Exceção em caso de erro na inicialização da classe
	 */
	public SignatureVerifier(CadesSignature signature, SignaturePolicyComponent signaturePolicyComponent)
			throws SignatureVerifierException, PbadException {
		initialize(signature, (SignatureVerifierParams) null);
	}

	/**
	 * Constrói um {@link SignatureVerifier} a partir da assinatura a ser
	 * verificada. Serão assumidos os parâmetros passados em <code>params</code>
	 * para verificação.
	 * @param signature A assinatura a ser verificada
	 * @param params Os parâmetros de verificação
	 * @param signaturePolicy A política de assinatura
	 * @throws PbadException Exceção em caso de erro na inicialização da classe
	 * @throws SignatureVerifierException
	 */
	public SignatureVerifier(CadesSignature signature, SignatureVerifierParams params,
			SignaturePolicyInterface signaturePolicy) throws PbadException, SignatureVerifierException {
		initialize(signature, params);
		this.signaturePolicy = signaturePolicy;
		AttributeMap.initialize();
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Constrói um {@link SignatureVerifier} a partir da assinatura a ser
	 * verificada. Serão assumidos os parâmetros passados em <code>params</code>
	 * para verificação.
	 * @param signature A assinatura a ser verificada
	 * @param params Os parâmetros de verificação
	 * @param cadesSignatureComponent COmponente de assinatura CAdES
	 * @throws PbadException Exceção em caso de erro na inicialização da classe
	 * @throws SignatureVerifierException
	 */
	public SignatureVerifier(CadesSignature signature, SignatureVerifierParams params,
			CadesSignatureComponent cadesSignatureComponent) throws PbadException, SignatureVerifierException {
		cadesSignatureComponent.signaturePolicyInterface.setActualPolicy(this.signature.getSignaturePolicyIdentifier(),
				this.signature.getSignaturePolicyUri(), AdESType.CAdES);
		this.component = cadesSignatureComponent;
		initialize(signature, params);

		AttributeMap.initialize();
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Verifica todos os campos da assinatura conforme especificado na PA da
	 * assinatura. Caso a assinatura não seja válida, os erros de validação
	 * serão disponibilizados no método <code>getSignatureValidationErros</code>
	 * .
	 * Todas as regras de verificação da política de assinatura seram levados em
	 * conta. Primeiro validando as regras para o caminho do assinante, depois
	 * verificando se os atributos obrigatórios estão todos presentes na
	 * assinatura, para então verificar a validade de cada atributo e por fim
	 * verificar a integridade da assinatura.
  	 * @param sigReport O relatório de verificação da assinatura
	 * @return Indica se a assinatura é válida
	 */
	public boolean verify(SignatureReport sigReport) {

		this.signerCert = null;
		if (this.getTimeReference() == null) {
			this.setTimeReference(new Time(SystemTime.getSystemTime()));
		}

		this.exceptions = new ArrayList<PbadException>();
		List<PbadException> warnings = new ArrayList<PbadException>();
		try {
			this.setSignerCert();
		} catch (SignerCertificationPathException e) {
			Application.logger.log(Level.WARNING, "Não foi possível obter o certificado do assinante", e);
		}

		if (this.signerCert != null) {
			sigReport.setSignerSubjectName(this.signerCert.getSubjectX500Principal().toString());
		} else {
			sigReport.setSignerSubjectName("Assinante desconhecido");
		}
		sigReport.setSignatureType(this.signature.getMode().name());
		sigReport.setRequiredRules(AttributeMap.translateNames(this.signaturePolicy.getMandatedSignedAttributeList()));
		sigReport.setProhibitedRules("not implemented.");
		sigReport.setPresent(true);
		sigReport.setForm(Form.SigningCertificate);
		sigReport.setCertificatesRequiredOnSignature(this.signaturePolicy.getMandatedCertificateInfo());

		/*
		 * Como este método configura o atributo `hash` da classe SignatureReport,
		 * é necessário verificar a integridade da assinatura antes dos atributos.
		 */
		this.verifySignIntegrity(sigReport);

		List<String> signatureAttributeList = this.signature.getAttributeList();
		List<String> mandatedSignedAttributeList = this.signaturePolicy.getMandatedSignedAttributeList();
		List<String> mandatedUnsignedAttributeList = this.signaturePolicy.getMandatedUnsignedVerifierAttributeList();
		/* Verifica se a assinatura contem todos os atributos obrigatórios */
		this.verifyPresenceOfMandatedAttributes(signatureAttributeList, mandatedSignedAttributeList,
				mandatedUnsignedAttributeList, sigReport);
		/* Faz a validação dos carimbos do tempo */
		List<TimeStamp> timeStamps;
		try {
			timeStamps = this.getOrderedTimeStamps();
			warnings = this.verifySignatureTimestamps(warnings, timeStamps, sigReport);
		} catch (Throwable e) {
			Application.logger.log(Level.SEVERE, "Erro ao validar os carimbos do tempo", e);
		}

		Set<TrustAnchor> trustAnchors = null;
		try {
			trustAnchors = this.signaturePolicy.getSigningTrustAnchors();
			this.certPath = this.component.certificateValidation.generateCertPath(signerCert, trustAnchors, getTimeReference());
		} catch (Throwable e) {
			Application.logger.log(Level.WARNING, "Não foi possível obter o certificado do assinante", e);
		}

		this.checkPolicyConstraints(this.exceptions);
		List<String> attributesAlreadyVerified = this.getTimeStampPriorityList();
		List<String> mandatedAttributes = new ArrayList<String>();
		mandatedAttributes.addAll(mandatedSignedAttributeList);
		mandatedAttributes.addAll(mandatedUnsignedAttributeList);
		/* Faz a validação de cada atributo restante */
		this.verifyAttributesInMandatedList(warnings, this.exceptions, signatureAttributeList, mandatedAttributes,
				attributesAlreadyVerified, sigReport);

		try {
			this.verifyUnmandatedAttributes(sigReport);
		} catch (SignatureAttributeException e) {
			this.exceptions.add(e);
			Application.logger.log(Level.SEVERE, "Erro ao validar os atributos opcionais", e);
		}

		ValidationResult validationResult = getCadesSignatureComponent().certificateValidation.validate(signerCert,
				trustAnchors, signaturePolicy.getSignerRevocationReqs(), getTimeReference(),
				sigReport);
		
		if(validationResult.getRevocationDate() != null && !sigReport.getStamps().isEmpty()) {
			
			Date revDate = validationResult.getRevocationDate();
			Time timeStampDate = getTemporaryTimeReference();
			if (timeStampDate == null) {
				timeStampDate = getTimeReference();
			}

			int last = sigReport.getStamps().size() - 1;
			if(timeStampDate.before(revDate)  && sigReport.getStamps().get(last).isValid()) {
				validationResult = ValidationResult.valid;
				validationResult.setMessage("Certificado revogado, porém valido na data do Carimbo do Tempo.");
			}
			
		}

		sigReport.verifyValidationResult(validationResult);
		this.exceptions.add(new PbadException(validationResult.getMessage()));

		try {
			this.verifyCertificatesInSignature(sigReport);
		} catch (CertificateException | IOException e) {
			Application.logger.log(Level.SEVERE, "Erro ao verificar a inclusão dos certificados na assinatura.", e);
		}


		/* Não ocorreram erros ao validar a assinatura? */
		boolean isValid = this.exceptions.size() == 0;
		/* Atualiza a lista de erros */
		this.exceptions.addAll(warnings);

		this.setTimeReference(this.getTimeReference());

		return isValid;
	}

	/**
	 * Verifica a presença dos certificados obrigatórios na assinatura. No caso
	 * de assinaturas XAdES são os certificados incluídos na estrutura KeyInfo.
	 * No caso de assinaturas CAdES são os certificados incluídos na estrutura
	 * Certificates.
	 * @param sigReport O relatório de verificação da assinatura
	 * @throws CertificateException Exceção em caso de erro na manipulação dos certificados
	 * @throws IOException Exceção em caso de erro na busca pelos certificados na assinatura
	 */
	private void verifyCertificatesInSignature(SignatureReport sigReport) throws CertificateException, IOException {
		CertInfoReq certInfo = this.signaturePolicy.getMandatedCertificateInfo();
		List<X509Certificate> certificates = this.signature.getCertificates();
		boolean correct = false;
		sigReport.setContainsMandatedCertificates(false);
		if (certInfo == CertInfoReq.SIGNER_ONLY) {
			correct = certificates.size() == 1 && certificates.get(0).equals(this.signerCert);
			sigReport.setContainsMandatedCertificates(correct);
		} else if (certInfo == CertInfoReq.FULL_PATH) {
			correct = this.getCertPath().getCertificates().size() == certificates.size();
			if (correct) {
				for (X509Certificate certificate : certificates) {
					correct &= this.getCertPath().getCertificates().contains(certificate);
				}
			}
			sigReport.setContainsMandatedCertificates(correct);
		} else {
			correct = true;
			sigReport.setContainsMandatedCertificates(true);
		}

		if (!correct) {
			this.exceptions.add(new PbadException("Não foram incluídos os certificados obrigatórios na assinatura."));
		}
	}

	/**
	 * Verifica a integridade da assinatura
	 * @param report O relatório de verificação da assinatura
	 * @return Indica se a assinatura está íntegra
	 */
	private boolean verifySignIntegrity(SignatureReport report) {

		boolean integrity = false;

		try {
			integrity = this.signature.verify(this.signerCert, report);
		} catch (VerificationException e) {
			this.exceptions.add(e);
		} catch (NullPointerException e) {
			this.exceptions.add(new PbadException(PbadException.INVALID_SIGNATURE));
		}

		return integrity;

	}

	/**
	 * Verifica os carimbos de tempo em ordem de tempo e atualiza a referência
	 * de tempo conforme a validação é executada.
	 * @param warnings Lista de alertas da verificação
	 * @param timeStamps Lista de carimbos de tempo
	 * @param sigReport O relatório de verificação da assinatura
	 * @return A lista de erros que ocorreram durante a verificação
	 * @throws PbadException Exceção em caso de erro na formação dos carimbos
	 */
	public List<PbadException> verifySignatureTimestamps(List<PbadException> warnings, List<TimeStamp> timeStamps,
			SignatureReport sigReport) throws PbadException {

		if (this.exceptions == null) {
			// coming from `CmsSignature#verifyTimeStamps`, which didn't call the `verify` method above
			this.exceptions = new ArrayList<>();
		}

		ArrayList<PbadException> insideWarnings = new ArrayList<PbadException>();
		String errorMessage = null;
		if (timeStamps.size() > 0) {
			String actualIdentifier = timeStamps.get(0).getIdentifier();
			boolean isMandated = this.signaturePolicy.getMandatedSignedAttributeList().contains(actualIdentifier)
					|| this.signaturePolicy.getMandatedUnsignedVerifierAttributeList().contains(actualIdentifier);
			boolean isAtLastOneValid = false;
			boolean isAtLeastOneExpired = false;
			boolean isAtLeastOneInvalid = false;
			for (TimeStamp timeStamp : timeStamps) {
				if (!timeStamp.getIdentifier().equals(actualIdentifier)) {
					if (!isAtLastOneValid) {
						this.exceptions.addAll(insideWarnings);
						insideWarnings = new ArrayList<PbadException>();
					} else {
						warnings.addAll(insideWarnings);
					}
					isAtLastOneValid = false;
					actualIdentifier = timeStamp.getIdentifier();
				}
				TimeStampReport timeStampReport = new TimeStampReport();
				AttribReport attribReport = new AttribReport();
				attribReport.setAttribName(AttributeMap.translateName(actualIdentifier));
				try {
					timeStamp.validate(timeStampReport, timeStamps);
					if (timeStampReport.getCertPathState().equals(SignatureReport.CertValidity.Expired.toString())) {
						errorMessage = timeStampReport.getCertPathMessage();
						insideWarnings.add(new SignatureAttributeException(errorMessage));
						sigReport.addTimeStampReport(timeStampReport);
						attribReport.setError(true);
					} else {
						isAtLastOneValid = true;
						sigReport.addTimeStampReport(timeStampReport);
						attribReport.setError(false);
					}
				} catch (NotInICPException notInICPException) {
					errorMessage = notInICPException.getMessage();
					attribReport.setError(AttribReport.HasBeenValidated.NOT_VALIDATED);
					isAtLeastOneInvalid = true;
				} catch (TimeStampException timeStampException) {
					if (!(timeStampException.getProblems().size() == 1 &&
							timeStampReport.getCertPathState().equals
									(SignatureReport.CertValidity.Expired.toString()))) {
						isAtLeastOneInvalid = true;
					} else {
						isAtLeastOneExpired = true;
					}
					insideWarnings.add(timeStampException);
					errorMessage = timeStampException.getMessage();
					sigReport.addTimeStampReport(timeStampReport);
					attribReport.setError(true);
				} catch (SignatureAttributeException signatureAttributeException) {
					insideWarnings.add(signatureAttributeException);
					errorMessage = signatureAttributeException.getMessage();
					sigReport.addTimeStampReport(timeStampReport);
					attribReport.setError(true);
					isAtLeastOneInvalid = true;
				} catch (Throwable t) {
					t.printStackTrace();
					errorMessage = t.getMessage();
					sigReport.addTimeStampReport(timeStampReport);
					attribReport.setError(true);
					isAtLeastOneInvalid = true;
				} finally {
					if (errorMessage != null) {
						attribReport.setErrorMessage(errorMessage);
					}
					if (isMandated) {
						sigReport.addAttribRequiredReport(attribReport);
					} else {
						sigReport.addAttribOptionalReport(attribReport);
					}
					if (!actualIdentifier.equals(IdAaSignatureTimeStampToken.IDENTIFIER)) {
						this.setTimeReference(timeStamp.getTimeReference());
					} else {
						this.setTemporaryTimeReference(timeStamp.getTimeReference());
					}
					errorMessage = null;
				}
			}
			if (!isAtLastOneValid) {
				this.exceptions.addAll(insideWarnings);
				insideWarnings = new ArrayList<PbadException>();
				// When there is not a valid timestamp, today's date is used
				this.setTimeReference(new Time(SystemTime.getSystemTime()));
			}
			sigReport.setHasOneValidTimeStamp(isAtLastOneValid);
			sigReport.setHasOneExpiredTimeStamp(isAtLeastOneExpired);
			sigReport.setHasOneInvalidTimeStamp(isAtLeastOneInvalid);
		}
		return insideWarnings;
	}

	/**
	 * Verifica a lista de attributos passados para garantir que a assinatura os
	 * possui
	 * @param signatureAttributeList Lista de atributos da assinatura
	 * @param mandatedSignedAttributeList Lista de atributos assinados obrigatórios
	 * @param mandatedUnsignedAttributeList Lista de não-atributos assinados obrigatórios
	 * @param sigReport O relatório de verificação da assinatura
	 */
	private void verifyPresenceOfMandatedAttributes(List<String> signatureAttributeList,
			List<String> mandatedSignedAttributeList, List<String> mandatedUnsignedAttributeList,
			SignatureReport sigReport) {

		for (String mandatedAttribute : mandatedSignedAttributeList) {
			if (!signatureAttributeList.contains(mandatedAttribute)) {
				SignatureAttributeNotFoundException signatureSignedAttributeNotFoundException = new SignatureAttributeNotFoundException(
						SignatureAttributeNotFoundException.MISSING_MANDATED_SIGNED_ATTRIBUTE, mandatedAttribute);
				AttribReport attribReport = new AttribReport();
				attribReport.setAttribName(AttributeMap.translateName(mandatedAttribute));
				attribReport.setError(true);
				String message = signatureSignedAttributeNotFoundException.getMessage();
				attribReport.setErrorMessage(message);
				sigReport.addAttribRequiredReport(attribReport);
				this.exceptions.add(signatureSignedAttributeNotFoundException);
			}
		}
		for (String mandatedAttribute : mandatedUnsignedAttributeList) {
			if (!signatureAttributeList.contains(mandatedAttribute)) {
				SignatureAttributeNotFoundException signatureUnsignedAttributeNotFoundException = new SignatureAttributeNotFoundException(
						SignatureAttributeNotFoundException.MISSING_MANDATED_UNSIGNED_ATTRIBUTE, mandatedAttribute);
				AttribReport attribReport = new AttribReport();
				attribReport.setAttribName(AttributeMap.translateName(mandatedAttribute));
				attribReport.setError(true);
				String message = signatureUnsignedAttributeNotFoundException.getMessage();
				attribReport.setErrorMessage(message);
				sigReport.addAttribRequiredReport(attribReport);
				this.exceptions.add(signatureUnsignedAttributeNotFoundException);
				signatureUnsignedAttributeNotFoundException.setCritical(false);
			}
		}
		boolean hasAttributeExceptions = !exceptions.isEmpty();
		sigReport.setPresenceOfInvalidAttributes(hasAttributeExceptions);
	}

	/**
	 * Verifica os atributos opcionais presentes na assinatura
	 * @param sigReport O relatório de verificação da assinatura
	 */
	public void verifyUnmandatedAttributes(SignatureReport sigReport) throws SignatureAttributeException {
		List<String> mandatedSignedAttributeList = this.signaturePolicy.getMandatedSignedAttributeList();
		List<String> mandatedUnsignedAttributeList = this.signaturePolicy.getMandatedUnsignedVerifierAttributeList();
		List<String> signatureAttributeList = this.signature.getAttributeList();
		List<String> attributesAlreadyVerified = this.getTimeStampPriorityList();
		List<String> mandatedAttributes = new ArrayList<String>();
		mandatedAttributes.addAll(mandatedSignedAttributeList);
		mandatedAttributes.addAll(mandatedUnsignedAttributeList);

		this.verifyOnlyUnmandatedAttributes(signatureAttributeList, mandatedAttributes, attributesAlreadyVerified,
				sigReport);
	}

	/**
	 * Retorna a lista dos erros que ocorreram na última validação.
	 * @return A lista de erros
	 */
	public List<PbadException> getSignatureValidationErrors() {
		List<PbadException> resulting = null;
		if (this.exceptions != null) {
			resulting = new ArrayList<PbadException>(this.exceptions);
		} else {
			resulting = new ArrayList<PbadException>();
		}
		return resulting;
	}

	/**
	 * Retorna os bytes do conteúdo assinado que foram passados no método
	 * <code> setSignedContent(byte[] signedContent) </code>.
	 * @return Os bytes do conteúdo assinado
	 */
	public byte[] getSignedContent() {
		return this.bytesOfSignedContent;
	}

	/**
	 * Retorna a assinatura que foi passada na construção da classe.
	 * @return A assinatura CAdES
	 */
	public CadesSignature getSignature() {
		return this.signature;
	}

	/**
	 * Verifica regras da política de assinatura que não são especificas de
	 * apenas um atributo, mas tem um contexto global, como por exemplo
	 * restrições de algortimos. Em caso de erros, eles serão adicionados à
	 * lista dada
	 * @param exceptions Lista de erros da verificação
	 */
	protected void checkPolicyConstraints(List<PbadException> exceptions) {
		try {
			this.checkExternalSignedData();
		} catch (PbadException signatureException) {
			exceptions.add(signatureException);
		}
		try {
			this.checkSignaturePolicyPeriod();
		} catch (SignatureAttributeException signatureAttributeException) {
			exceptions.add(signatureAttributeException);
		} catch (EncodingException encodingException) {
			exceptions.add(encodingException);
		}
		if (!this.checkKeyLength()) {
			exceptions.add(new SignatureConformityException(SignatureConformityException.INVALID_SIZE_KEY));
		}
		/*
		 * Caso não tenha sido possível construir o caminho de certificação,
		 * também não é possível verificar as políticas de certificação
		 * aceitáveis
		 */
		// if (this.certPath != null && this.certPath.getCertificates().size() >
		// 0) {
		try {
			this.checkAcceptablePolicies();
		} catch (CertificationPathException certificationPathException) {
			exceptions.add(certificationPathException);
		}

		try {
			this.checkAlgorithmsConstraints();
		} catch (OperatorCreationException | VerificationException e) {
			exceptions.add(new SignatureConformityException(
					SignatureConformityException.INVALID_ALGORITHM));
		}

	}

	/**
	 * Verifica se o algoritmo especificado na Política de Assinatura é o mesmo
	 * usado na assinatura.
	 * @throws VerificationException Exceção em caso de erro na verificação
	 * @throws OperatorCreationException Exceção em caso de erro na manipulação da assinatura
	 */
	protected void checkAlgorithmsConstraints()
			throws OperatorCreationException, VerificationException {

		if (!this.signaturePolicy.getSignatureAlgorithmIdentifier().equals("")) {
			AlgorithmIdentifier algId = new AlgorithmIdentifier(
					new ASN1ObjectIdentifier(this.signaturePolicy.getSignatureAlgorithmIdentifier()));
			AlgorithmIdentifier digId = new AlgorithmIdentifier(
					new ASN1ObjectIdentifier(this.signaturePolicy.getHashAlgorithmId()));

			this.signature.getSignerInformationVerifier(this.signerCert).getContentVerifier(algId,
					digId);
		}

	}

	/**
	 * Percorre o caminho de certificação verificando se as políticas usadas
	 * para cada certificado se encontram dentro das permitidas pela política de
	 * assinatura.
	 */
	protected void checkAcceptablePolicies() throws CertificationPathException {
		// @SuppressWarnings("unchecked")
		// List<X509Certificate> certPathCertificates = (List<X509Certificate>)
		// this.certPath.getCertificates();
		// X509Certificate lastCa =
		// certPathCertificates.get(certPathCertificates.size() - 1);
		// CertificateTrustPoint trustPoint =
		// this.signaturePolicy.getTrustPoint(lastCa.getIssuerX500Principal());
		// checkAcceptablePolicies(trustPoint);
	}

	/**
	 * Checa se o tamanho da chave usada para assinar é compatível com o tamanho
	 * mínimo exigido pela PA.
	 * @return Indica se o tamanho da chave do assinante é igual ou maior que o exigido
	 */
	protected boolean checkKeyLength() {
		boolean lengthIsAcceptable = false;
		CadesSignatureInformation cadesSignerInformation = (CadesSignatureInformation) this.signature;
		int keyLength = cadesSignerInformation.getSignerInformation().getSignature().length;
		keyLength = keyLength * 8;
		lengthIsAcceptable = keyLength >= this.signaturePolicy.getMinKeyLength();
		return lengthIsAcceptable;
	}

	/**
	 * Verifica se a assinatura foi feita dentro do período válido para o uso de
	 * políticas.
	 * @return Indica se a assinatura está dentro do período válido
	 *         para o uso de políticas
	 */
	protected boolean checkSignaturePolicyPeriod() throws SignatureAttributeException, EncodingException {
		boolean result = true;
		SigningPeriod signaturePeriod = this.signaturePolicy.getSigningPeriod();
		Time estimatedSignatureCreation = this.getTimeReference();
		if (signaturePeriod == null) {
			result = false;
		} else {
			if (estimatedSignatureCreation.before(signaturePeriod.getNotBefore())
					|| estimatedSignatureCreation.after(signaturePeriod.getNotAfter())) {
				result = false;
			}
		}
		return result;
	}

	/**
	 * Verifica se a assinatura está respeitando a regra da política de
	 * assinatura sobre o dado assinado ser interno, externo ou indiferente
	 * @return Indica se a assinatura está de acordo com a política
	 */
	protected boolean checkExternalSignedData() throws PbadException {
		boolean result;
		ExternalSignedData externalData = this.signaturePolicy.getExternalSignedData();
		if (externalData == ExternalSignedData.EXTERNAL) {
			result = this.signature.isExternalSignedData();
		} else if (externalData == ExternalSignedData.INTERNAL) {
			result = !this.signature.isExternalSignedData();
		} else
			result = true;
		return result;
	}

	/**
	 * Retorna uma lista com todos os atributos de Carimbo do Tempo existentes
	 * na assinatura que foram referenciados na lista de prioridade. Passa por
	 * todos os atributos da assinatura, instanciando e adicionando na lista de
	 * retorno aqueles que tem um identificador referenciado na lista de
	 * prioridade.
	 * @return A lista de carimbos de tempo na assinatura
	 * @throws SignatureAttributeException Exceção em caso de erro nos atributos da assinatura
	 * @throws UnknowAttributeException Exceção em caso de atributo desconhecido na assinatura
	 */
	private List<TimeStamp> getTimeStamps() throws SignatureAttributeException, UnknowAttributeException {
		List<String> completeAttributeList = this.getSignature().getAttributeList();
		Map<String, Integer> indexes = new HashMap<String, Integer>();
		List<TimeStamp> timeStampList = new ArrayList<TimeStamp>();
		TimeStamp timeStampInstance = null;
		List<String> timeStampPriorityList = this.getTimeStampPriorityList();
		for (String identifier : completeAttributeList) {
			if (timeStampPriorityList.contains(identifier)) {
				if (!indexes.containsKey(identifier)) {
					indexes.put(identifier, 0);
				}
				Class<?> attributeClass = null;
				Constructor<?> constructor = null;
				attributeClass = AttributeMap.getAttributeClass(identifier);
				if (attributeClass == null) {
					throw new UnknowAttributeException(UnknowAttributeException.UNKNOW_ATTRIBUTE, identifier);
				}
				try {
					constructor = attributeClass
							.getConstructor(new Class<?>[] { AbstractVerifier.class, Integer.class });
				} catch (SecurityException securityException) {
					throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + identifier,
							securityException.getStackTrace());
				} catch (NoSuchMethodException noSuchMethodException) {
					throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + identifier,
							noSuchMethodException.getStackTrace());
				}
				try {
					timeStampInstance = (TimeStamp) constructor.newInstance(this, indexes.get(identifier));
				} catch (IllegalArgumentException illegalArgumentException) {
					illegalArgumentException.printStackTrace();
					throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE
							+ identifier, illegalArgumentException.getStackTrace());
				} catch (InstantiationException illegalArgumentException) {
					illegalArgumentException.printStackTrace();
					throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE
							+ identifier, illegalArgumentException.getStackTrace());
				} catch (IllegalAccessException illegalArgumentException) {
					illegalArgumentException.printStackTrace();
					throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE
							+ identifier, illegalArgumentException.getStackTrace());
				} catch (InvocationTargetException illegalArgumentException) {
					illegalArgumentException.printStackTrace();
					throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE
							+ identifier, illegalArgumentException.getStackTrace());
				}
				int counter = indexes.get(identifier);
				counter++;
				indexes.put(identifier, counter);
				timeStampList.add(timeStampInstance);
			}
		}
		return timeStampList;
	}

	/**
	 * Retorna uma lista de atributos de Carimbo do Tempo (aqueles referenciados
	 * na lista de prioridade) ordenada por identificador, de acordo com o
	 * especificado na lista de prioridade, e com cada grupo de mesmo
	 * identificador ordenado por tempo (TimeReference). Na ordenação por tempo,
	 * é considerado que o tempo mais recente (ou seja, maior) tem maior
	 * prioridade.
	 * @return A lista de carimbo de tempo ordenada
	 * @throws SignatureAttributeException Exceção em caso de erro nos atributos da assinatura
	 * @throws UnknowAttributeException Exceção em caso de atributo desconhecido na assinatura
	 */
	public List<TimeStamp> getOrderedTimeStamps() throws EncodingException, SignatureAttributeException,
			UnknowAttributeException {
		List<TimeStamp> disorderedTimeStampList = this.getTimeStamps();
		List<TimeStamp> timeStampListSortedByIdentifier = this
				.getTimeStampListSortedByIdentifier(disorderedTimeStampList);
		List<TimeStamp> timeStampListSortedByIdentifierAndTime = new ArrayList<TimeStamp>();
		List<TimeStamp> timeStampSeparatedByIdentifier = new ArrayList<TimeStamp>();
		while (timeStampListSortedByIdentifier.size() != 0) {
			TimeStamp timeStamp = timeStampListSortedByIdentifier.get(0);
			String identifier = timeStamp.getIdentifier();
			timeStampSeparatedByIdentifier.add(timeStamp);
			timeStampListSortedByIdentifier.remove(timeStamp);
			boolean sameIdentifier = true;
			while (timeStampListSortedByIdentifier.size() != 0 && sameIdentifier) {
				TimeStamp nextTimeStamp = timeStampListSortedByIdentifier.get(0);
				sameIdentifier = identifier.equals(nextTimeStamp.getIdentifier());
				if (sameIdentifier) {
					timeStampSeparatedByIdentifier.add(nextTimeStamp);
					timeStampListSortedByIdentifier.remove(nextTimeStamp);
				}
			}
			if (timeStampSeparatedByIdentifier.size() > 1) {
				Collections.sort(timeStampSeparatedByIdentifier);
			}
			timeStampListSortedByIdentifierAndTime.addAll(timeStampSeparatedByIdentifier);
			timeStampSeparatedByIdentifier.clear();
		}
		return timeStampListSortedByIdentifierAndTime;
	}

	/**
	 * Ordena a lista de carimbos do tempo de acordo com seu identificador, na
	 * ordem estabelecida na lista de prioridades.
	 * @param disorderedTimeStampList A Lista de Carimbos do Tempo desordenada
	 * @return A lista de carimbos ordenada de acordo com a prioridade
	 */
	private List<TimeStamp> getTimeStampListSortedByIdentifier(List<TimeStamp> disorderedTimeStampList) {
		List<TimeStamp> timeStampListSortedByIdentifier = new ArrayList<TimeStamp>();
		List<String> timeStampPriorityList = this.getTimeStampPriorityList();
		for (String priorityIdentifier : timeStampPriorityList) {
			for (TimeStamp timeStamp : disorderedTimeStampList) {
				String identifier = timeStamp.getIdentifier();
				if (identifier.compareTo(priorityIdentifier) == 0) {
					timeStampListSortedByIdentifier.add(timeStamp);
				}
			}
		}
		return timeStampListSortedByIdentifier;
	}

	/**
	 * Retorna a política de assinatura
	 * @return A política de assinatura
	 */
	@Override
	public SignaturePolicyInterface getSignaturePolicy() {
		return this.signaturePolicy;
	}

	/**
	 * Retorna o relatório da política de assinatura
	 * @return O relatório da política de assinatura
	 * @throws SignatureAttributeException Exceção em caso de erro no atributo
	 * @throws EncodingException Exceção em caso de má formação da política
	 */
	public PaReport getPaReport() throws SignatureAttributeException, EncodingException {
		PaReport report = this.signaturePolicy.getReport();
		report.setPaExpired(!checkSignaturePolicyPeriod());
		return report;
	}
}
