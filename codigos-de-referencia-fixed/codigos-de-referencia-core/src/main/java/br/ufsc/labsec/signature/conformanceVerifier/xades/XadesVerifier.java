package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.io.File;
import java.io.OutputStream;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.*;
import java.util.logging.Level;

import br.ufsc.labsec.signature.SignaturePolicyInterface.AdESType;
import br.ufsc.labsec.signature.SystemTime;
import br.ufsc.labsec.signature.conformanceVerifier.cms.exceptions.SignatureNotICPBrException;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.ValidationDataService;
import org.w3c.dom.DOMException;
import org.w3c.dom.Element;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.CertificateCollection;
import br.ufsc.labsec.signature.Constants;
import br.ufsc.labsec.signature.Verifier;
import br.ufsc.labsec.signature.conformanceVerifier.report.PaReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.Report;
import br.ufsc.labsec.signature.conformanceVerifier.report.Report.ReportType;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.ValidationDataReport;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.CertificateTrustPoint;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.CounterSignatureInterface;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SigningCertificateInterface;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SignaturePolicyIdentifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SigningCertificate;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.ArchiveTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CertificateValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CompleteCertificateRefs;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CompleteRevocationRefs;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.RevocationValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.SigAndRefsTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.SignatureTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.RevocationValuesException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.XadesSignatureContainerException;
import br.ufsc.labsec.signature.exceptions.AIAException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import br.ufsc.labsec.signature.exceptions.VerificationException;

/**
 * Esta classe implementa os métodos para verificação de um documento assinado XAdES.
 * Estende {@link AbstractXadesSigner} e implementa {@link Verifier}.
 */
public class XadesVerifier extends AbstractXadesSigner implements Verifier {

	private static List<String> ATTRIBUTES_AVAILABLE = null;

	static {
		ATTRIBUTES_AVAILABLE = new ArrayList<String>();
		ATTRIBUTES_AVAILABLE.add(SignatureTimeStamp.IDENTIFIER);
		ATTRIBUTES_AVAILABLE.add(SigAndRefsTimeStamp.IDENTIFIER);
		ATTRIBUTES_AVAILABLE.add(CompleteCertificateRefs.IDENTIFIER);
		ATTRIBUTES_AVAILABLE.add(CompleteRevocationRefs.IDENTIFIER);
		ATTRIBUTES_AVAILABLE.add(CertificateValues.IDENTIFIER);
		ATTRIBUTES_AVAILABLE.add(RevocationValues.IDENTIFIER);
		ATTRIBUTES_AVAILABLE.add(ArchiveTimeStamp.IDENTIFIER);
	}

	/**
	 * Componente de assinatura XAdES
	 */
	private XadesSignatureComponent component;
	/**
	 * Contêiner de assinaturas XAdES
	 */
	private XadesSignatureContainer signatureContainer;
	/**
	 * Assinatura selecionada para verificação
	 */
	private XadesSignature selectedSignature;
	/**
	 * Relatório da verificação do documento de assinatura
	 */
	private Report report;
	/**
	 * Relatório da verificação da assinatura
	 */
	private SignatureReport signatureReport;
	/**
	 * Fábrica de atributos
	 */
	protected AttributeFactory attributeFactory;
	/**
	 * Indica se a assinatura sofreu modificações
	 */
	private boolean modified;

	/**
	 * Construtor
	 * @param xadesSignatureComponent Componente de assinatura XAdES
	 */
	public XadesVerifier(XadesSignatureComponent xadesSignatureComponent) {
		super(xadesSignatureComponent);
		this.component = xadesSignatureComponent;
		selectedAttributes = new ArrayList<>();
	}

	/**
	 * Retorna a assinatura selecionada
	 * @return A assinatura XAdES selecionada
	 */
	public XadesSignature getSelectedSignature() {
		return this.selectedSignature;
	}

	/**
	 * Retorna a lista de assinaturas presentes no documento, sem considerar contra-assinaturas
	 * @return A lista de assinaturas do documento
	 */
	@Override
	public List<String> getSignaturesAvailable() {
		if (this.signatureContainer != null) {
			int signatureCount = this.signatureContainer.getSignatureCount();

			List<String> result = new ArrayList<String>();

			for (int i = 0; i < signatureCount; i++) {
				extractSignatureName(result, i);
			}

			return result;
		}

		return null;
	}

	/**
	 * Retorna uma lista de issuerName+serialNumber dos certificados na assinatura indicada
	 * pelo índice dado
	 * @param result A lista de issuerName+serialNumber dos certificados presentes
	 *            na assinatura
	 * @param signatureIndex A posição que a assinatura se encontra no SignatureContainer
	 */
	private void extractSignatureName(List<String> result, int signatureIndex) {
		XadesSignature xadesSignature = this.signatureContainer
				.getSignatureAt(signatureIndex);

		if (xadesSignature.getAttributeList().contains(SigningCertificate.IDENTIFIER)) {
			SigningCertificate signingCertificate = null;
			try {
				signingCertificate = new SigningCertificate(xadesSignature.getEncodedAttribute(SigningCertificate.IDENTIFIER));
			} catch (SignatureAttributeNotFoundException e) {
				Application.logger.log(Level.SEVERE, "Erro não foi possível encontrar a assinatura.", e);
			} catch (EncodingException e) {
				Application.logger.log(Level.SEVERE, "Erro não foi possível decodificar a assinatura.", e);
			}
			result.add(signatureIndex + "#" + signingCertificate.getIssuerName() + " "
					+ signingCertificate.getSerialNumber());
		}
	}

	/**
	 * Adiciona novos certificados e CRLs ao SignatureIdentityInformation da assinatura
	 * de acordo com a presença dos atributos CertificateValues e RevocationValues
	 * @param xadesSignature A assinatura XAdES
	 */
	private void addValidationData(XadesSignature xadesSignature) {
		List<X509Certificate> certValuesCertificates;
		List<X509CRL> crlsList;
		List<X509Certificate> certs = xadesSignature.getCertificatesAtKeyInfo();
		this.component.getSignatureIdentityInformation().addCertificates(certs);
		if (xadesSignature.getAttributeList().contains(
				CertificateValues.IDENTIFIER)) {
			certValuesCertificates = this.getCertificateValues(xadesSignature);
			this.component.getSignatureIdentityInformation().addCertificates(certValuesCertificates);
			if (xadesSignature.getAttributeList().contains(RevocationValues.IDENTIFIER)) {
				crlsList = this.getSignatureRevocationValues(xadesSignature);
				this.component.getSignatureIdentityInformation().addCrl(certValuesCertificates, crlsList);
			}
		}

		if (certs != null && certs.size() == 1) {
			CertPath certPath = null;
			Certificate cert = certs.get(0);
			try {
				Set<TrustAnchor> trustAnchors = this.component.signaturePolicyInterface.getSigningTrustAnchors();
				certPath = this.component.certificateValidation.generateCertPath(cert, trustAnchors, new Time(
								new Date().getTime()));
			} catch (Throwable e) {
				Application.logger.log(Level.WARNING,
						"Não foi possível obter o certificado do assinante", e);
			}
			if (certPath != null) {
				this.component.getSignatureIdentityInformation()
						.addCertificates((List<X509Certificate>) certPath.getCertificates());
			}
		}
	}

	/**
	 * Retorna a lista de CRLs do atributo RevocationValues
	 * @param xadesSignature A assinatura XAdES
	 * @return A lista de CRLs dos certificados presentes na assinatura
	 */
	private List<X509CRL> getSignatureRevocationValues(
			XadesSignature xadesSignature) {
		RevocationValues revValues = null;
		try {
			Element element = xadesSignature
					.getEncodedAttribute(RevocationValues.IDENTIFIER);
			revValues = new RevocationValues(element);
			return revValues.getCrlValues();
		} catch (SignatureAttributeNotFoundException e) {
			Application.logger.log(Level.SEVERE,
					"Atributo não encontrado na assinatura", e);
		} catch (RevocationValuesException e) {
			Application.logger.log(Level.SEVERE,
					"Erro no atributo RevocationValues", e);
		} catch (SignatureAttributeException e) {
			Application.logger.log(Level.SEVERE,
					"Erro no atributo RevocationValues da assinatura", e);
		}

		return null;
	}

	/**
	 * Carrega as informações da assinatura indicada no contâiner XAdES
	 * @param target O identificador da assinatura
	 */
	@Override
	public void selectSignature(String target) {
		
		this.signatureReport = new SignatureReport();
		String[] splittedSignatureCount = target.split("#");
		String[] splittedSignatureTarget = splittedSignatureCount[1].split("/");

		this.selectedSignature = null;

        int sigIndex = Integer.parseInt(splittedSignatureCount[0]);
        XadesSignature auxSelectedSignature = this.signatureContainer.getSignatureAt(sigIndex);

        X509Certificate cert = auxSelectedSignature.getCertificatesAtKeyInfo().get(0);

        String auxSelectedSignatureSubjectAtString = cert.getIssuerX500Principal().toString() + " " + cert.getSerialNumber();

        splittedSignatureTarget[0] = splittedSignatureTarget[0].replace(", ", ",");
        auxSelectedSignatureSubjectAtString = auxSelectedSignatureSubjectAtString.replace(", ", ",");

        if (splittedSignatureTarget[0].compareToIgnoreCase(auxSelectedSignatureSubjectAtString) == 0) {
            selectedSignature = auxSelectedSignature;
        }

        addValidationData(this.signatureContainer.getSignatureAt(sigIndex));

		for (int i = 1; i < splittedSignatureTarget.length; i++) {

			String xadesSignatureSubject = selectedSignature
					.getCertificatesAtKeyInfo().get(0)
					.getSubjectX500Principal().getName();

			List<CounterSignatureInterface> cs = selectedSignature
					.getCounterSignatures();
			for (CounterSignatureInterface counterSignatureInterface : cs) {
				String csiSubjectString = ((XadesSignature) counterSignatureInterface)
						.getCertificatesAtKeyInfo().get(0)
						.getSubjectX500Principal().getName();
				if (csiSubjectString.equals(xadesSignatureSubject)) {
					selectedSignature = (XadesSignature) counterSignatureInterface;
				}
			}
		}

		this.xadesSignatureComponent.signaturePolicyInterface.setActualPolicy(
				selectedSignature.getSignaturePolicyIdentifier(),
				selectedSignature.getSignaturePolicyUri(), AdESType.XAdES);
		
		AIAException aiaException = null;

		try {
			
			List<X509Certificate> certs = selectedSignature.getCertificatesAtKeyInfo();	
					
			if (!certs.isEmpty() && certs.get(0) != null) {
				this.addCertificatesToValidation(signatureReport, certs.get(0));
			}

			SignatureVerifier verifier = new SignatureVerifier(selectedSignature, this.xadesSignatureComponent);

			verifier.verify(signatureReport);

			this.report.addSignatureReport(signatureReport);

			PaReport paReport = verifier.getPaReport();
			this.report.addPaReport(paReport);
			signatureReport.setSignaturePolicy(paReport.getOid());
		} catch (EncodingException e) {
			Application.logger.log(Level.SEVERE, "A assinatura não foi codificada corretamente.", e);
		} catch (SignatureAttributeException e) {
			Application.logger.log(Level.SEVERE, "Não foi possível encontrar os certificados.", e);
		} catch (PbadException e) {
			Application.logger.log(Level.SEVERE, "Não foi possível obter os certificados da Assinatura via AIA.", e);
		}
	}

	/**
	 * Realiza a verificação dos certificados e CRLs do caminho de certificação da assinatura
	 * e adiciona os resultados ao relatório da assinatura
	 * @param sigReport O relatório da verificação da assinatura
	 * @param cert O certificado do assinante
	 * @throws AIAException Exceção em caso de erro ao obter o caminho de certificação
	 */
	protected void addCertificatesToValidation(SignatureReport sigReport, Certificate cert) {
		if (sigReport != null) {
			Set<TrustAnchor> trustAnchors = this.xadesSignatureComponent.signaturePolicyInterface.getSigningTrustAnchors();
			Time timeReference = new Time(SystemTime.getSystemTime());
			CertPath certPath = this.component.certificateValidation.generateCertPath(cert, trustAnchors, timeReference);
			List<? extends Certificate> certificates = certPath.getCertificates();

			for (int i = 0; i < certificates.size() - 1; i++) {
				X509Certificate subjectCert = (X509Certificate) certificates.get(i);
				X509Certificate issuerCert = (X509Certificate) certificates.get(i + 1);

				sigReport.addValidation(getValidationData(subjectCert, issuerCert));
			}
			X509Certificate lastCert = (X509Certificate) certificates.get(certificates.size() - 1);
			CertificateTrustPoint trustPoint = this.xadesSignatureComponent.signaturePolicyInterface
					.getTrustPoint(lastCert.getIssuerX500Principal());
			if (trustPoint != null) {
				sigReport.addValidation(getValidationData(lastCert, (X509Certificate) trustPoint.getTrustPoint()));
			}
		}

	}

	/**
	 * Retorna o certificado do assinante
	 * @param signingCertificate Identificador do certificado
	 * @return O certificado do assinante ou nulo caso não seja encontrado
	 */
	//FIXME Por que não é usado?
	private X509Certificate getCertificate(SigningCertificateInterface signingCertificate) {

		List<CertificateCollection> certificateCollections = this.component.certificateCollection;

		X509Certificate certificate = null;
		int i = 0;

		while (certificate == null && i < certificateCollections.size()) {
			certificate = (X509Certificate) certificateCollections.get(i).getCertificate(signingCertificate);
			i++;
		}

		return certificate;
	}

	/**
	 * Realiza a verificação dos certificados dados e suas CRLs
	 * @param subjectCert Certificado do assinante
	 * @param issuerCert Certificado do emissor
	 * @return O relatório da verificação
	 */
	private static ValidationDataReport getValidationData(X509Certificate subjectCert, X509Certificate issuerCert) {
		ValidationDataReport validationData = new ValidationDataReport();

		validationData.setCertificateOnline(false);
		boolean valid = true;

		try {
			subjectCert.verify(issuerCert.getPublicKey());
		} catch (Exception e) {
			valid = false;
		}

		validationData.setValidCertificate(valid);

		validationData.setCertificateIssuerName(subjectCert.getIssuerX500Principal().toString());

		validationData.setNotBefore(subjectCert.getNotBefore());

		validationData.setNotAfter(subjectCert.getNotAfter());

		validationData.setCertificateSubjectName(subjectCert.getSubjectX500Principal().getName());

		validationData.setCertificateSerialNumber(subjectCert.getSerialNumber().toString());

		return validationData;
	}

	/**
	 * Retorna a lista de certificados do atributo CertificateValues
	 * @param xadesSignature A assinatura XAdES
	 * @return A lista de certificados presente no atributo da assinatura
	 *         CertificateValues
	 */
	public List<X509Certificate> getCertificateValues(
			XadesSignature xadesSignature) {
		CertificateValues certValues = null;
		try {
			Element element = xadesSignature
					.getEncodedAttribute(CertificateValues.IDENTIFIER);
			certValues = new CertificateValues(element);
			return certValues.getCertValues();
		} catch (SignatureAttributeNotFoundException e) {
			Application.logger.log(Level.SEVERE,
					"Atributo não encontrado na assinatura", e);
		} catch (EncodingException e) {
			Application.logger.log(Level.SEVERE,
					"Erro ao codificar o atributo CertValues", e);
		} catch (br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.CertValuesException e) {
			Application.logger.log(Level.SEVERE, "Erro no atributo CertValues",
					e);
		}

		return null;
	}

	/**
	 * Retorna os atributos que podem ser inseridos na assinatura selecionada
	 * @return Os atributos que podem ser inseridos na assinatura
	 */
	@Override
	public List<String> getAvailableAttributes() {
		return XadesVerifier.ATTRIBUTES_AVAILABLE;
	}

	/**
	 * Adiciona um atributo
	 * @param attribute Nome do atributo que deve ser inserido
	 * @return Indica se a inserção foi bem sucedida
	 */
	@Override
	public boolean addAttribute(String attribute) {
		
		if(!super.selectedAttributes.contains(attribute)) {
			super.selectedAttributes.add(attribute);
			this.modified = true;
			
			try {
				signature.addUnsignedAttribute(attributeFactory.getAttribute(attribute));
			} catch (DOMException | PbadException e) {
				Application.logger.log(Level.SEVERE, e.getMessage(), e);
				return false;
			}
						
			return true;
				
		}
		return false;
	}

	/**
	 * Limpa as informações do verificador
	 * @return Indica se a limpeza foi bem sucedida
	 */
	@Override
	public boolean clear() {
		if(this.modified) {
			OutputStream out = component.ioService.save("xml");
		
			if (out != null) {
				try {
					this.signatureContainer.encode(out);
				} catch (EncodingException e) {
					Application.logger.log(Level.SEVERE, e.getMessage(), e);
					return false;
				}
			}
		}
		this.selectedSignature = null;
		this.signatureContainer = null;
		this.report = null;

		super.selectedAttributes.clear();
		this.modified = false;
		
		return true;
	}

	/**
	 * Cria um objeto {@link Report} com as informações da verificação
	 * @param target O documento a ser verificado
	 * @param content O conteúdo assinado do documento XAdES
	 * @param type Tipo de relatório desejado
	 * @return O relatório da verificação
	 * @throws VerificationException Exceção caso haja algum problema na verificação
	 */
	@Override
	public Report report(byte[] target, byte[] content, ReportType type) throws VerificationException {
		createReport();

		this.selectTarget(target, content);
		List<String> signaturesAvailable = this.getSignaturesAvailable();
		for (String signature : signaturesAvailable) {
			this.selectSignature(signature);
			this.selectTarget(target, content);
		}

		this.xadesSignatureComponent.signaturePolicyInterface
				.getLpaReport(report, AdESType.XAdES);

		return this.report;

	}

	/**
	 * Inicializa um objeto {@link Report}
	 */
	private void createReport() {
			this.report = new Report();
			report.setSoftwareName(Constants.VERIFICADOR_NAME);
			report.setSoftwareVersion(Constants.SOFTWARE_VERSION);
			report.setVerificationDate(new Date());
			report.setSourceOfDate("Offline");
	}

	/**
	 * Inicializa os bytes do documento XAdES assinado
	 * @param target Os bytes do documento XAdES assinado
	 * @param content Os bytes do conteúdo assinado no documento
	 * @throws VerificationException Exceção caso os bytes não sejam uma assinatura válida
	 */
	public void selectTarget(byte[] target, byte[] content) throws VerificationException {
		try {
			this.signatureContainer = new XadesSignatureContainer(target);
		} catch (XadesSignatureContainerException e) {
			Application.logger.log(Level.SEVERE, e.getMessage(), e);
			throw new VerificationException(e);
		}

		if(this.signatureContainer.getSignatureCount() == 0) {
			throw new VerificationException("Impossivel decodificar a assinatura.");
		}
		
		if (content != null) {
			this.signatureContainer.setContent(content);
		}
	}

	/**
	 * Adiciona o relatório de contra-assinatura passado ao relatório da assinatura
	 * @param signatureReport O relatório de contra-assinatura a ser adicionado
	 */
	public void addCounterSignatureToSignatureReport(SignatureReport signatureReport) {
		this.signatureReport.addCounterSignatureReport(signatureReport);
	}

	/**
	 * Verifica se a assinatura possui conteúdo destacado
	 * @return Indica se a assinatura possui conteúdo destacado
	 */
	@Override
	public boolean needSignedContent() {
		return this.signatureContainer.hasDetachedContent();
	}

	/**
	 * Verifica se o documento é uma assinatura XAdES
	 * @param filePath Diretório do arquivo a ser verificado
	 * @return Indica se o arquivo é uma assinatura XAdES
	 */
	@Override
	public boolean isSignature(String filePath) {
		try {

			XadesSignatureContainer sig = new XadesSignatureContainer(new File(
					filePath));
			return sig.getSignatureCount() > 0;
		} catch (XadesSignatureContainerException e) {
			Application.logger.log(Level.FINE, e.getMessage(), e);
			return false;
		}
	}

	/**
	 * Retorna uma lista de atributos obrigatórios
	 * @return Uma lista de atributos obrigatórios
	 */
	@Override
	public List<String> getMandatedAttributes() {
		List<String> mandatedAttributes = new ArrayList<String>(this.component.signaturePolicyInterface.getMandatedUnsignedVerifierAttributeList());

		return mandatedAttributes;
	}

	/**
	 * Retorna o relatório da validação de uma assinatura
	 * @return O relatório da validação de uma assinatura
	 */
	@Override
	public SignatureReport getValidationResult() {
		return this.signatureReport;
	}

	/**
	 * Realiza a assinatura de um documento
	 * @param signatureContainerGenerator Gerador de contêineres de assinaturas XAdES
	 * @return A assinatura gerada
	 */
	@Override
	protected Signature sign(SignatureContainerGenerator signatureContainerGenerator) {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * Verifica se o documento assinado é uma assinatura XAdES
	 * @param sig Os bytes do documento assinado
	 * @param detached Os bytes do arquivo destacado
	 * @return Indica se o documento assinado é uma assinatura XAdES
	 * @throws SignatureNotICPBrException Exceção caso a assinatura não seja feita
	 * com um certificado ICP-Brasil
	 */
	@Override
	public boolean supports(byte[] sig, byte[] detached) throws SignatureNotICPBrException {
		try {
			this.selectTarget(sig, detached);
			List<XadesSignature> signatures = this.signatureContainer.getSignatures();

			if (!signatures.isEmpty()) {
				boolean validSignature = true;
				Iterator<XadesSignature> itSign = this.signatureContainer.getSignatures().iterator();
				while (itSign.hasNext() && validSignature) {
					validSignature = this.validSignature(itSign.next());
				}
				return validSignature;
			}
		} catch (VerificationException | EncodingException | ClassCastException e) {
			return false;
		}

		return false;
	}

	/**
	 * Verifica se a assinatura foi feita com um certificado ICP-Brasil e se é uma assinatura XAdES
	 * @param s A assinatura a ser verificada
	 * @return Indica se a assinatura é uma assinatura XAdES e ICP-Brasil
	 * @throws SignatureNotICPBrException Exceção caso a assinatura não seja feita com um
	 * certificado ICP-Brasil
	 */
	private boolean validSignature(XadesSignature s) throws SignatureNotICPBrException {
		boolean containsValidPolicy = false;
		boolean isICPBR = false;
		X509Certificate certificate = s.getCertificatesAtKeyInfo().get(0);
		isICPBR = this.checkCertPath(certificate);
		if (!isICPBR) {
			throw new SignatureNotICPBrException("Signer certificate is not from ICP-Brasil.");
		}
		containsValidPolicy = s.getAttributeList().contains(SignaturePolicyIdentifier.IDENTIFIER);

		return containsValidPolicy && isICPBR;
	}

	/**
	 * Verifica se é possível criar o caminho de certificação da assinatura
	 * @param cert Certificado utilizado na assinatura
	 * @return Indica se o caminho de certificação foi criado com sucesso
	 */
	private boolean checkCertPath(X509Certificate cert) {
		Set<TrustAnchor> trustAnchors = this.xadesSignatureComponent.signaturePolicyInterface.getSigningTrustAnchors();
		Time timeReference = new Time(SystemTime.getSystemTime());
		CertPath certPath = xadesSignatureComponent.certificateValidation.generateCertPathNoSave(cert, trustAnchors, timeReference);

		return certPath != null;
	}
}
