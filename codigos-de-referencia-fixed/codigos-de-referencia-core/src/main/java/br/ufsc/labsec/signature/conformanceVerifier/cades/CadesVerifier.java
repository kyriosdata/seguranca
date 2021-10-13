package br.ufsc.labsec.signature.conformanceVerifier.cades;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.CertificateCollection;
import br.ufsc.labsec.signature.Constants;
import br.ufsc.labsec.signature.SignaturePolicyInterface.AdESType;
import br.ufsc.labsec.signature.SystemTime;
import br.ufsc.labsec.signature.Verifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SigningCertificateInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificate;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificateV2;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.*;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.CadesSignatureException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.CertValuesException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.conformanceVerifier.cms.exceptions.SignatureNotICPBrException;
import br.ufsc.labsec.signature.conformanceVerifier.report.PaReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.Report;
import br.ufsc.labsec.signature.conformanceVerifier.report.Report.ReportType;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.CertificateTrustPoint;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.ValidationDataService;
import br.ufsc.labsec.signature.exceptions.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.*;
import java.sql.Time;
import java.util.*;
import java.util.logging.Level;

/**
 * Esta classe implementa os métodos para verificação de uma assinatura CAdES.
 * Implementa {@link Verifier}.
 */
public class CadesVerifier implements Verifier {

	private static final String SIGNINGCERTIFICATEV1_ATTRIBUTE_DECODING_ERROR = "Não foi possível decodificar corretamente o atributo SigningCertificate";
	private static final String SIGNINGCERTIFICATEV2_ATTRIBUTE_DECODING_ERROR = "Não foi possível decodificar o atributo SigningCertificateV2";
	private static final String GET_ATTRIBUTE_FAILED = "Obtenção de atributo falhou";
	private static final String ATTRIBUTE_NOT_FOUND = "Atributo não encontrado na assinatura";
	/**
	 * Contêiner de assinatura CAdES
	 */
	private CadesSignatureContainer signatureContainer;
	/**
	 * Assinatura selecionada para verificação
	 */
	private CadesSignature selectedSignature;
	/**
	 * Componente de assinatura CAdES
	 */
	private CadesSignatureComponent cadesSignature;
	/**
	 * Relatório da verificação do documento de assinatura
	 */
	private Report report;
	/**
	 * Relatório da verificação da assinatura
	 */
	private SignatureReport signatureReport;
	/**
	 * Gerenciador de atributos
	 */
	private CadesAttributeIncluder attributeIncluder;
	/**
	 * Indica se algum atributo foi adicionado
	 */
	private boolean attributesAdded;
	/**
	 * Tipo da política de assinatura
	 */
	private AdESType policyType;
	/**
	 * Indica se a assinatura é assinada com uma política de assinatura CAdES
	 * (para diferenciar de assinaturas PAdES, que também utilizam este verificador)
	 */
	private boolean isCadesOID;
	/**
	 * Identificador da política de assinatura
	 */
	private String oid;

	/**
	 * Construtor
	 * @param cadesSignature Componente de assinatura CAdES
	 */
	public CadesVerifier(CadesSignatureComponent cadesSignature) {
		this.cadesSignature = cadesSignature;
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Retorna o identificador da política de assinatura
	 * @return O identificador da política de assinatura
	 */
	public String getOid() {
		return oid;
	}

	/**
	 * Retorna a lista de assinaturas presentes no documento
	 * @return A lista de assinaturas do documento
	 */
	@Override
	public List<String> getSignaturesAvailable() {
		if (this.signatureContainer != null) {
			List<CadesSignature> signatures = null;
			try {
				signatures = this.signatureContainer.getSignatures();
			} catch (EncodingException e) {
				e.printStackTrace();
			}
			List<String> names = new ArrayList<String>();
			SigningCertificateInterface idAaSigningCertificate = null;

			idAaSigningCertificate = addCertificatesAndAddNameFromSigningCertificate(
					signatures, names, idAaSigningCertificate, this.signatureReport);

			return names;
		}

		return null;
	}

	/**
	 * Busca pelo certificado do assinante e o adiciona na lista de issuer+serial dada
	 * @param signatures Lista de assinaturas CAdES
	 * @param names Lista de issuer+serial do certificado do signatário presente
	 *            no atributo
	 * @param idAaSigningCertificate Atributo presente na assinatura
	 * @param sigReport O relatório de verificação da assinatura
	 * @return O atributo SigningCertificate da assinatura
	 */
	private SigningCertificateInterface addCertificatesAndAddNameFromSigningCertificate(
			List<CadesSignature> signatures, List<String> names,
			SigningCertificateInterface idAaSigningCertificate, SignatureReport sigReport) {
		for (CadesSignature signature : signatures) {
			idAaSigningCertificate = addNameFromSigningCertificate(names,
					idAaSigningCertificate, signature);

		}
		return idAaSigningCertificate;
	}

	/**
	 * Busca pelo certificado do assinante e o adiciona na lista de issuer+serial dada
	 * @param names Lista de issuer+serial do certificado do signatário presente
	 *            no atributo
	 * @param idAaSigningCertificate Atributo presente na assinatura
	 * @param signature Assinatura CAdES
	 * @return O atributo SigningCertificate da assinatura
	 */
	private SigningCertificateInterface addNameFromSigningCertificate(
			List<String> names,
			SigningCertificateInterface idAaSigningCertificate,
			CadesSignature signature) {
		if (signature.getAttributeList().contains(
				IdAaSigningCertificate.IDENTIFIER)) {
			idAaSigningCertificate = getNameFromSigningCertificateV1(names,
					idAaSigningCertificate, signature);
		} else {
			idAaSigningCertificate = getNameFromSigningCertificateV2(names,
					idAaSigningCertificate, signature);
		}
		return idAaSigningCertificate;
	}

	/**
	 * Adiciona novos certificados e CRLs ao SignatureIdentityInformation da assinatura
	 * de acordo com a presença dos atributos CertificateValues e RevocationValues
	 * @param signature A assinatura CAdES
	 * @param sigReport O relatório de verificação da assinatura
	 * @throws CertificateException Ocorre esta exceção quando for encontrado algum erro no
	 *             certificado
	 * @throws IOException Ocorre esta exceção quando for encontrado algum erro no
	 *             arquivo de entrada/saída
	 */
	private void addValidationData(CadesSignature signature, SignatureReport sigReport) throws CertificateException, IOException {
		List<X509Certificate> certValuesCertificates;
		List<X509CRL> crlsList;

		List<X509Certificate> certs = signature.getCertificates();
		this.cadesSignature.getSignatureIdentityInformation().addCertificates(certs);
		
		if (signature.getAttributeList().contains(IdAaEtsCertValues.IDENTIFIER)) {
			certValuesCertificates = this.getSignatureCertificateValues(signature);
			this.cadesSignature.getSignatureIdentityInformation().addCertificates(certValuesCertificates);

			if (signature.getAttributeList().contains(IdAaEtsRevocationValues.IDENTIFIER)) {
				crlsList = this.getSignatureRevocationValues(signature);
				this.cadesSignature.getSignatureIdentityInformation().addCrl(certValuesCertificates, crlsList);
			}
			
			if(signature.getAttributeList().contains(IdAaSignatureTimeStampToken.IDENTIFIER)) {
				
			}
			if(signature.getAttributeList().contains(IdAaEtsEscTimeStamp.IDENTIFIER)) {
				
			}
			if(signature.getAttributeList().contains(IdAaEtsArchiveTimeStampV2.IDENTIFIER)) {
				
			}
		}
		
		if(certs != null && certs.size() == 1){
			CertPath certPath = null;
			Certificate cert = certs.get(0);
			try {
				Set<TrustAnchor> trustAnchors = this.cadesSignature.signaturePolicyInterface.getSigningTrustAnchors();
				certPath = this.cadesSignature.certificateValidation.generateCertPath(cert, trustAnchors, new Time(SystemTime.getSystemTime()));
			} catch (Throwable e) {
				Application.logger.log(Level.WARNING, "Não foi possível obter o certificado do assinante", e);
			}
			if(certPath != null){ 
				this.cadesSignature.getSignatureIdentityInformation().addCertificates((List<X509Certificate>) certPath.getCertificates());
			}
		}
		

	}

	/**
	 * Realiza a verificação dos certificados e CRLs do caminho de certificação da assinatura
	 * e adiciona os resultados ao relatório da assinatura
	 * @param sigReport O relatório da verificação da assinatura
	 * @param cert O certificado do assinante
	 * @throws AIAException Exceção em caso de erro ao obter o caminho de certificação
	 */
	protected void addCertificatesToValidation(
			SignatureReport sigReport, Certificate cert) {
		if (sigReport != null) {
			Set<TrustAnchor> trustAnchors = this.cadesSignature.signaturePolicyInterface.getSigningTrustAnchors();
			Time timeReference = new Time(SystemTime.getSystemTime());
			CertPath certPath = this.cadesSignature.certificateValidation.generateCertPath(cert, trustAnchors, timeReference);
			List<? extends Certificate> certificates = certPath.getCertificates();

			for (int i = 0; i < certificates.size() - 1; i++) {
				X509Certificate subjectCert = (X509Certificate) certificates.get(i);
				X509Certificate issuerCert = (X509Certificate) certificates.get(i + 1);

				sigReport.addValidation(ValidationDataService.getValidationData(subjectCert, issuerCert));

			}
			X509Certificate lastCert = (X509Certificate) certificates.get(certificates.size() - 1);
			CertificateTrustPoint trustPoint = this.cadesSignature.signaturePolicyInterface
					.getTrustPoint(lastCert.getIssuerX500Principal());
			if (trustPoint != null) {
				sigReport.addValidation(ValidationDataService.getValidationData(
						lastCert,
						(X509Certificate) trustPoint.getTrustPoint()));
			}
		}

	}

	/**
	 * Retorna a lista de certificados do atributo IdAaEtsCertValues
	 * @param signature A assinatura CAdES
	 * @return A lista de certificados presente no atributo da assinatura
	 *         CertificateValues
	 */
	public List<X509Certificate> getSignatureCertificateValues(
			CadesSignature signature) {
		IdAaEtsCertValues idAaEtsCertValues = null;
		try {
			Attribute attribute = signature
					.getEncodedAttribute(IdAaEtsCertValues.IDENTIFIER);
			idAaEtsCertValues = new IdAaEtsCertValues(attribute);
		} catch (SignatureAttributeNotFoundException e) {
			Application.logger.log(Level.SEVERE, ATTRIBUTE_NOT_FOUND, e);
		} catch (CertValuesException e) {
			Application.logger.log(Level.SEVERE, "Erro no atributo CertValues",
					e);
		}

		return idAaEtsCertValues.getCertValues();
	}

	/**
	 * Busca pelo certificado do assinante e o adiciona na lista de issuer+serial dada
	 * @param names Lista de issuer+serial do certificado do signatário presente
	 *            no atributo
	 * @param idAaSigningCertificate Atributo presente na assinatura
	 * @param signature Assinatura CAdES
	 * @return O atributo SigningCertificateV1 da assinatura
	 */
	private SigningCertificateInterface getNameFromSigningCertificateV1(
			List<String> names,
			SigningCertificateInterface idAaSigningCertificate,
			CadesSignature signature) {
		Attribute attribute = null;
		try {
			attribute = signature
					.getEncodedAttribute(IdAaSigningCertificate.IDENTIFIER);
		} catch (SignatureAttributeNotFoundException e) {
			Application.logger.log(Level.SEVERE, GET_ATTRIBUTE_FAILED, e);
		}
		try {
			if (attribute != null) {
				idAaSigningCertificate = new IdAaSigningCertificate(attribute);
			}
		} catch (Throwable e) {
			Application.logger.log(Level.SEVERE,
					SIGNINGCERTIFICATEV1_ATTRIBUTE_DECODING_ERROR, e);
		}

		boolean nameFound = true;
		if (idAaSigningCertificate != null) {
			try {
				List<CertificateCollection> certList = cadesSignature.certificateCollection; 
			 	
				X509Certificate certificate = null; 
				int i = 0; 

				while (i < certList.size() && certificate == null) {
					certificate = (X509Certificate) certList.get(i).getCertificate(idAaSigningCertificate); 
					i++;
				}
				
				if (certificate != null) {
					names.add(certificate.getSubjectX500Principal().toString());
				} else {
					names.add("Issuer: "
							+ idAaSigningCertificate.getESSCertID().get(0)
							.getIssuerSerial().getIssuer().toString()
							+ ", Serial:"
							+ idAaSigningCertificate.getESSCertID().get(0)
							.getIssuerSerial().getSerial().toString());
				}
			} catch (Throwable t) {
				Application.logger.log(Level.SEVERE,
						SIGNINGCERTIFICATEV1_ATTRIBUTE_DECODING_ERROR, t);
				nameFound = false;
			}
		} else {
			nameFound = false;
		}

		if (!nameFound) {
			names.add("Signature" + names.size() + 1);
		}
		return idAaSigningCertificate;
	}

	/**
	 * Busca pelo certificado do assinante e o adiciona na lista de issuer+serial dada
	 * @param names Lista de issuer+serial do certificado do signatário presente
	 *            no atributo
	 * @param idAaSigningCertificate Atributo presente na assinatura
	 * @param signature Assinatura CAdES
	 * @return O atributo SigningCertificateV2 da assinatura
	 */
	private SigningCertificateInterface getNameFromSigningCertificateV2(
			List<String> names,
			SigningCertificateInterface idAaSigningCertificate,
			CadesSignature signature) {
		Attribute attribute = null;
		try {
			attribute = signature
					.getEncodedAttribute(IdAaSigningCertificateV2.IDENTIFIER);
			if (attribute != null) {
				idAaSigningCertificate = new IdAaSigningCertificateV2(attribute);
			}
		} catch (SignatureAttributeNotFoundException e) {
			Application.logger.log(Level.SEVERE, GET_ATTRIBUTE_FAILED, e);
		} catch (SignatureAttributeException e) {
			Application.logger.log(Level.SEVERE,
					SIGNINGCERTIFICATEV2_ATTRIBUTE_DECODING_ERROR, e);
		}

		boolean nameFound = true;
		nameFound = isNameFound(names, idAaSigningCertificate, nameFound);

		if (!nameFound) {
			names.add("Signature" + names.size() + 1);
		}
		return idAaSigningCertificate;
	}

	/**
	 * Busca pelo certificado do assinante e o adiciona na lista de issuer+serial dada
	 * @param names Lista de issuer+serial do certificado do signatário presente
	 *            no atributo
	 * @param idAaSigningCertificate Atributo presente na assinatura
	 * @param nameFound Indica se o issuer+serial foi encontrado
	 * @return Indica se o issuerSerial foi encontrado
	 */
	private boolean isNameFound(List<String> names,
			SigningCertificateInterface idAaSigningCertificate,
			boolean nameFound) {
		if (idAaSigningCertificate != null) {
			nameFound = addIssuerSerial(names, idAaSigningCertificate,
					nameFound);
		} else {
			nameFound = false;
		}
		return nameFound;
	}

	/**
	 * Busca pelo certificado do assinante e o adiciona na lista de issuer+serial dada
	 * @param names Lista de issuer+serial do certificado do signatário presente
	 *            no atributo
	 * @param idAaSigningCertificate Atributo presente na assinatura
	 * @param nameFound Indica se o issuer+serial foi encontrado
	 * @return Indica se o issuerSerial foi encontrado
	 */
	private boolean addIssuerSerial(List<String> names,
			SigningCertificateInterface idAaSigningCertificate,
			boolean nameFound) {
		try {
			List<CertificateCollection> certList = cadesSignature.certificateCollection; 
		 	

			X509Certificate certificate = null;
			int i = 0;
			
			while (i < certList.size() && certificate == null) {
				certificate = (X509Certificate) certList.get(i).getCertificate(idAaSigningCertificate); 
				i++; 
			}			
			
			if (certificate != null) {
				names.add(certificate.getSubjectX500Principal().toString());
			} else {
				// System.out.println("get (0) : "+idAaSigningCertificateV2.getESSCertIdV2().get(0).getIssuerSerial());
				// names.add("Issuer: "
				// +
				// idAaSigningCertificateV2.getESSCertIdV2().get(0).getIssuerSerial().getIssuer().toString()
				// + ", Serial:"
				// +
				// idAaSigningCertificateV2.getESSCertIdV2().get(0).getIssuerSerial().getSerial().toString());
				nameFound = false;
			}
		} catch (Throwable t) {
			Application.logger.log(Level.SEVERE,
					SIGNINGCERTIFICATEV1_ATTRIBUTE_DECODING_ERROR, t);
			nameFound = false;
		}
		return nameFound;
	}

	/**
	 * Carrega as informações da assinatura indicada no contâiner CAdES
	 * @param signatureSelected O identificador da assinatura
	 */
	@Override
	public void selectSignature(String signatureSelected) {

		this.signatureReport = new SignatureReport();

		try {

			this.selectedSignature = this.signatureContainer.getSignatureAt(Integer.parseInt(signatureSelected));

			if (this.policyType == null || this.policyType == AdESType.CAdES) {
				try {
					this.cadesSignature.signaturePolicyInterface.setActualPolicy(
							selectedSignature.getSignaturePolicyIdentifier(),
							selectedSignature.getSignaturePolicyUri(), AdESType.CAdES);
					this.setPolicyType(AdESType.CAdES);
				} catch (Exception e) {
					this.cadesSignature.signaturePolicyInterface.setDefaultPolicy();
				}
            }

			addValidationData(this.selectedSignature, this.signatureReport);
			this.addCertificatesToValidation(signatureReport, this.selectedSignature.getSigningCertificate());

			SignatureVerifier verifier = new SignatureVerifier(this.selectedSignature, this.cadesSignature);

			this.signatureReport.setSchema(SignatureReport.SchemaState.VALID);
			verifier.verify(this.signatureReport);
			this.report.addSignatureReport(this.signatureReport);

			PaReport paReport = verifier.getPaReport();
			this.report.addPaReport(paReport);
			this.signatureReport.setSignaturePolicy(paReport.getOid());

		} catch (EncodingException e) {
			Application.logger.log(Level.SEVERE, "A assinatura não foi codificada corretamente.", e);
		} catch (SignatureAttributeException | CertificateException | IOException e) {
			Application.logger.log(Level.SEVERE, "Não foi possível encontrar os certificados.", e);
		} catch (PbadException e) {
			Application.logger.log(Level.SEVERE, "Não foi possível inicializar o verificador", e);
		}

	}

	/**
	 * Limpa as informações do verificador
	 * @return Indica se a limpeza foi bem sucedida
	 */
	@Override
	public boolean clear() {
		
		this.selectedSignature = null;
		this.signatureContainer = null;
		this.report = null;
		this.policyType = null;
		
		if (this.attributesAdded) {

			AttributeFactory attributeFactory = new AttributeFactory(attributeIncluder);

			for (String attribute : this.attributeIncluder.getSelectedAttributes()) {
				try {
					selectedSignature.addUnsignedAttribute(attributeFactory.getAttribute(attribute));
				} catch (CertificateEncodingException
						| NoSuchAlgorithmException | PbadException
						| IOException | TSPException e) {
					Application.logger.log(Level.SEVERE, e.getMessage(), e);
					return false;
				}
			}

			OutputStream outputStream = this.cadesSignature.ioService
					.save("p7s");
			if (outputStream != null) {
				try {
					this.signatureContainer.encode(outputStream);
				} catch (EncodingException e) {
					Application.logger.log(Level.SEVERE, e.getMessage(), e);
					return false;
				}
			}
		}
		
		return true;
	}

	/**
	 * Retorna o relatório da verificação de uma assinatura
	 * @return O relatório da verificação de uma assinatura
	 */
	@Override
	public SignatureReport getValidationResult() {
		return this.signatureReport;
	}

	/**
	 * Cria um objeto {@link Report} com as informações da verificação
	 * @param target O documento a ser verificado
	 * @param signedContent O conteúdo assinado do documento CAdES
	 * @param type Tipo de relatório desejado
	 * @return O relatório da verificação
	 * @throws VerificationException Exceção caso haja algum problema na verificação
	 */
	@Override
	public Report report(byte[] target, byte[] signedContent, ReportType type) throws VerificationException {
		Security.addProvider(new BouncyCastleProvider());

		createReport();

        selectTarget(target, signedContent);
		List<String> signaturesAvailable = null;
		signaturesAvailable = getSignaturesAvailable();
		for (int i = 0; i < signaturesAvailable.size(); i++) {
			selectSignature(Integer.toString(i));
			// getValidationResults();
		}

		this.cadesSignature.signaturePolicyInterface.getLpaReport(this.report, AdESType.CAdES);
		return this.report;
	}

	/**
	 * Inicializa um objeto {@link Report}
	 */
	public void createReport() {
		if (this.report == null) {
			this.report = new Report();
			report.setSoftwareName(Constants.VERIFICADOR_NAME);
			report.setSoftwareVersion(Constants.SOFTWARE_VERSION);
			report.setVerificationDate(new Date());
			report.setSourceOfDate("Offline");
		}
	}

	/**
	 * Retorna o relatório da verificação do arquivo de assinatura
	 * @return O relatório de verificação
	 */
	public Report getReport() {
		return this.report;
	}

	public void setSelectedSignature(CadesSignature signature) {
		this.selectedSignature = signature;
	}

	/**
	 * Inicializa os bytes do documento CAdES
	 * @param target Os bytes do documento CAdES
	 * @param signedContent Os bytes do conteúdo assinado no documento
	 * @throws VerificationException Exceção caso os bytes não sejam uma assinatura válida
	 */
	@Override
	public void selectTarget(byte[] target, byte[] signedContent)
			throws VerificationException {
		byte[] signatureBytes = target;
		try {
			this.signatureContainer = new CadesSignatureContainer(
					signatureBytes);
		} catch (CadesSignatureException e1) {
			throw new VerificationException(e1);
		} catch (EncodingException | NullPointerException e1) {
			throw new VerificationException(e1);
		}
		byte[] signedContentBytes = null;
		try {
			if (this.signatureContainer.hasDetachedContent()) {
				if (signedContent != null) {
					signedContentBytes = signedContent;
					try {
						this.signatureContainer
								.setSignedContent(signedContentBytes);
					} catch (PbadException e) {
						Application.logger.log(Level.SEVERE,
								"Erro ao ler o conteudo assinado", e);
						throw new VerificationException(e);
					}
				}
			}
		} catch (EncodingException e) {
			Application.logger.log(Level.SEVERE, "Erro ao ler a assinatura", e);
			throw new VerificationException(e);
		}
	}	

	public CadesSignature getSelectedSignature() {
		return this.selectedSignature;
	}

	/**
	 * Retorna os bytes do arquivo indicado
	 * @param filePath O endereço do arquivo
	 * @return Os bytes do arquivo
	 */
    private byte[] getFileBytes(String filePath) {

        File file = new File(filePath);
        FileInputStream inputStream = null;
        try {
            inputStream = new FileInputStream(file);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        byte[] fileBytes = null;
        try {
            fileBytes = Streams.readAll(inputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return fileBytes;
    }

	/**
	 * Retorna a lista de CRLs do atributo IdAaEtsRevocationValues
	 * @param signature A assinatura CAdES
	 * @return A lista de CRLs dos certificados presentes na assinatura
	 */
	public List<X509CRL> getSignatureRevocationValues(CadesSignature signature) {
		IdAaEtsRevocationValues idAaEtsRevocationValues = null;

		try {
			Attribute attribute = signature
					.getEncodedAttribute(IdAaEtsRevocationValues.IDENTIFIER);
			idAaEtsRevocationValues = new IdAaEtsRevocationValues(attribute);
		} catch (SignatureAttributeNotFoundException e) {
			Application.logger.log(Level.SEVERE, ATTRIBUTE_NOT_FOUND, e);
		} catch (SignatureAttributeException e) {
			Application.logger.log(Level.SEVERE,
					"Erro no atributo RevocationValues", e);
		}

		return idAaEtsRevocationValues.getCrlValues();
	}

	/**
	 * Retorna os atributos que podem ser inseridos na assinatura selecionada
	 * @return Os atributos que podem ser inseridos na assinatura
	 */
	@Override
	public List<String> getAvailableAttributes() {
		List<String> attributesAvailable = new ArrayList<String>();

		attributesAvailable.add(AttributeFactory.id_aa_ets_CertificateRefs);
		attributesAvailable.add(AttributeFactory.id_aa_ets_revocationRefs);
		// attributesAvailable.add(AttributeFactory.id_aa_ets_attrCertificateRefs);
		// attributesAvailable.add(AttributeFactory.id_aa_ets_attrRevocationRefs);
		attributesAvailable.add(AttributeFactory.id_aa_ets_escTimeStamp);
		attributesAvailable.add(AttributeFactory.id_aa_ets_certValues);
		attributesAvailable.add(AttributeFactory.id_aa_ets_revocationValues);
		attributesAvailable.add(AttributeFactory.id_aa_ets_archiveTimeStampV2);
		attributesAvailable.add(AttributeFactory.id_aa_signatureTimeStamp);

		return attributesAvailable;
	}

	/**
	 * Adiciona um atributo
	 * @param attribute Nome do atributo que deve ser inserido
	 * @return Indica se a inserção foi bem sucedida
	 */
	@Override
	public boolean addAttribute(String attribute) {
		if (!this.attributeIncluder.getSelectedAttributes().contains(attribute)) {
			this.attributeIncluder.getSelectedAttributes().add(attribute);
		}

		this.attributesAdded = true;
		return true;
	}

	/**
	 * Verifica se a assinatura possui conteúdo destacado
	 * @return Indica se a assinatura possui conteúdo destacado
	 */
	@Override
	public boolean needSignedContent() {
		if (this.signatureContainer != null) {
			try {
				return this.signatureContainer.hasDetachedContent();
			} catch (EncodingException e) {
				Application.logger.log(Level.SEVERE, e.getMessage(), e);
			}
		}

		return false;
	}

	/**
	 * Verifica se o arquivo é um arquivo assinado CAdES
	 * @param filePath O endereço do arquivo a ser verificado
	 * @return Indica se o arquivo é um arquivo assinado CAdES
	 */
	@Override
	public boolean isSignature(String filePath) {
		byte[] signatureBytes = getFileBytes(filePath);
		try {
			new CadesSignatureContainer(signatureBytes);
		} catch (Exception e) {
			Application.logger.log(Level.FINE, e.getMessage(), e);
			return false;
		}

		return true;
	}

	/**
	 * Retorna uma lista de atributos obrigatórios
	 * @return A lista de atributos obrigatórios
	 */
	@Override
	public List<String> getMandatedAttributes() {
		List<String> mandatedAttributes = new ArrayList<String>();
		for (String attributeOid : this.cadesSignature.signaturePolicyInterface
				.getMandatedUnsignedVerifierAttributeList()) {
			mandatedAttributes.add(AttributeFactory.translateOid(attributeOid));
		}

		return mandatedAttributes;
	}

	/**
	 * Retorna o componente de assinatura CAdES
	 * @return O componente da assinatura
	 */
	public CadesSignatureComponent getCadesSignature() {
		return cadesSignature;
	}

	/**
	 * Verifica se o documento assinado é uma assinatura CAdES
	 * @param sig Os bytes do documento assinado
	 * @param detached Os bytes do arquivo destacado
	 * @return Indica se o documento assinado é uma assinatura CAdES
	 * @throws SignatureNotICPBrException Exceção caso a assinatura não seja feita com um certificado ICP-Brasil
	 */
	@Override
	public boolean supports(byte[] sig, byte[] detached) throws SignatureNotICPBrException {
		try {
			this.selectTarget(sig, detached);
			List<CadesSignature> signatures = this.signatureContainer.getSignatures();

			if (!signatures.isEmpty()) {
				boolean validSignature = true;
				Iterator<CadesSignature> itSign = this.signatureContainer.getSignatures().iterator();
				while (itSign.hasNext() && validSignature) {
					validSignature = this.validSignature(itSign.next());
				}
				return validSignature;
			}
		} catch (VerificationException | EncodingException e) {
			return false;
		}

        return false;
	}

	/**
	 * Verifica se a assinatura foi feita com um certificado ICP-Brasil e se é uma assinatura CAdES
	 * @param s A assinatura a ser verificada
	 * @return Indica se a assinatura é uma assinatura CAdES e ICP-Brasil
	 * @throws SignatureNotICPBrException Exceção caso a assinatura não seja feita com um certificado ICP-Brasil
	 */
	private boolean validSignature(CadesSignature s) throws SignatureNotICPBrException {
		boolean containsValidPolicy = false;
		boolean isICPBR = false;
		this.isCadesOID = false;
		this.oid = null;
		try {
			X509Certificate certificate = s.getSigningCertificate();
			isICPBR = this.checkCertPath(certificate);
			if (!isICPBR) {
				throw new SignatureNotICPBrException("Signer certificate is not from ICP-Brasil.");
			}
			containsValidPolicy = s.getAttributeList().contains(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId.toString());
			oid = s.getSignaturePolicyIdentifier();
			String cadesPolicy = "2\\.16\\.76\\.1\\.7\\.1\\.[1-5]\\.(.*)";
			this.isCadesOID = oid.matches(cadesPolicy);
		} catch (CertificateException | IOException | PbadException | NullPointerException e) {
			Application.logger.log(Level.WARNING, "Erro ao obter certificados de CadesSignature.", e.getMessage());
		}
		return containsValidPolicy && isICPBR;
	}

	/**
	 * Verifica se é possível criar o caminho de certificação da assinatura
	 * @param certificate Certificado utilizado na assinatura
	 * @return Indica se o caminho de certificação foi criado com sucesso
	 */
	private boolean checkCertPath(X509Certificate cert) {
		Set<TrustAnchor> trustAnchors = this.cadesSignature.signaturePolicyInterface.getSigningTrustAnchors();
		Time timeReference = new Time(SystemTime.getSystemTime());

		CertPath certpath = this.cadesSignature.certificateValidation.generateCertPathNoSave(cert, trustAnchors, timeReference);

		return certpath != null;
	}

	/**
	 * Atribue o tipo da política de assinatura
	 * @param policyType O tipo da política
	 */
    public void setPolicyType(AdESType policyType) {
		if (this.policyType == null)
			this.policyType = policyType;
	}

	/**
	 * Retorna o tipo da política de assinatura
	 * @return O tipo da política
	 */
    AdESType getPolicyType() {
        return policyType;
    }

	/**
	 * Informa se a política de assinatura é CAdES
	 * @return Indica se a política de assinatura é CAdES
	 */
	public boolean isCadesOID() {
		return isCadesOID;
	}
}
