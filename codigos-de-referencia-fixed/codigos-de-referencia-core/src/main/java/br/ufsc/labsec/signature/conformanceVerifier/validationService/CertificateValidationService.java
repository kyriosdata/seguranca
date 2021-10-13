package br.ufsc.labsec.signature.conformanceVerifier.validationService;

import java.security.*;
import java.security.cert.*;
import java.security.cert.CertPathValidatorException.BasicReason;
import java.security.cert.CertPathValidatorException.Reason;
import java.security.cert.Certificate;
import java.sql.Time;
import java.util.*;
import java.util.logging.Level;

import javax.security.auth.x500.X500Principal;

import br.ufsc.labsec.signature.SystemTime;
import br.ufsc.labsec.signature.exceptions.AIAException;
import br.ufsc.labsec.signature.exceptions.CertificateCollectionException;
import org.bouncycastle.cert.ocsp.OCSPResp;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.CertificateCollection;
import br.ufsc.labsec.signature.CertificateValidation;
import br.ufsc.labsec.signature.RevocationInformation;
import br.ufsc.labsec.signature.RevocationInformation.CRLResult;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.CertRevReq;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.exceptions.LCRException;

/**
 * Esta classe realiza a validação de um certificado e sua LCR
 */
public class CertificateValidationService implements CertificateValidation {

	/**
	 * Certificado com erro
	 */
	private Certificate certWithError;
	/**
	 * CRL com erro
	 */
	private CRL crlWithError;
	/**
	 * Mensagem de erro
	 */
	private String messageError;
	/**
	 * Mapa que relaciona os motivos de erro com suas mensagens
	 */
	private Map<Reason, String> reasons;
	/**
	 * Componente de repositório PKCS12
	 */
	private ValidationServiceRepository vsRepository;
	/**
	 * Cache de LCRs. O mapa relaciona a LCR com o seu status
	 */
	private Map<CRL, CRLResult> crlCacheMap;
	/**
	 * Mapa que relaciona o certificado com o seu caminho de certificação
	 */
	private Map<Certificate, CertPath> certPaths;

	/**
	 * Construtor
	 * @param validationService Componente de repositório PKCS12
	 */
	public CertificateValidationService(ValidationServiceRepository validationService) {
		this.vsRepository = validationService;

		this.crlCacheMap = new HashMap<>();
		this.certPaths = new HashMap<>();

		reasons = new HashMap<Reason, String>();

		reasons.put(BasicReason.ALGORITHM_CONSTRAINED, CertificationPathException.ALGORITHM_CONSTRAINED);
		reasons.put(BasicReason.EXPIRED, CertificationPathException.EXPIRED_CERTIFICATE);
		reasons.put(BasicReason.INVALID_SIGNATURE, CertificationPathException.INVALID_SIGNATURE);
		reasons.put(BasicReason.NOT_YET_VALID, CertificationPathException.CERTIFICATE_NOT_VALID_YET);
		reasons.put(BasicReason.REVOKED, CertificationPathException.REVOKED_CERTIFICATE);
		reasons.put(BasicReason.UNDETERMINED_REVOCATION_STATUS, CertificationPathException.UNDETERMINED_REVOCATION_STATUS);
		reasons.put(BasicReason.UNSPECIFIED, CertificationPathException.UNSPECIFIED);

		reasons.put(PKIXReason.INVALID_KEY_USAGE, CertificationPathException.INVALID_KEY_USAGE);
		reasons.put(PKIXReason.INVALID_NAME, CertificationPathException.INVALID_NAME);
		reasons.put(PKIXReason.INVALID_POLICY, CertificationPathException.INVALID_POLICY);
		reasons.put(PKIXReason.NAME_CHAINING, CertificationPathException.NAME_CHAINING);
		reasons.put(PKIXReason.NO_TRUST_ANCHOR, CertificationPathException.NO_TRUST_ANCHOR);
		reasons.put(PKIXReason.NOT_CA_CERT, CertificationPathException.NOT_CA_CERT);
		reasons.put(PKIXReason.PATH_TOO_LONG, CertificationPathException.PATH_TOO_LONG);
		reasons.put(PKIXReason.UNRECOGNIZED_CRIT_EXT, CertificationPathException.UNRECOGNIZED_CRIT_EXT);

	}

	/**
	 * Valida o certificado e seu caminho de certificação
	 * @param certificate O certificado a ser validado
	 * @param trustAnchors As âncoras de confiança para o caminho de certificação
	 * @param revocationRequirements Requerimentos de revogação
	 * @param timeReference Data de referência da validação
	 * @param sigReport Relatório da assinatura
	 * @return O resultado da validação
	 */
	@Override
	public ValidationResult validate(Certificate certificate, Set<TrustAnchor> trustAnchors,
			CertRevReq revocationRequirements, Time timeReference, SignatureReport sigReport) {

		if (certificate == null || trustAnchors == null || revocationRequirements == null || timeReference == null) {
			return ValidationResult.validationNotPossible;
		}

		ValidationResult result = ValidationResult.valid;

		messageError = "";
		certWithError = null;
		X509Certificate x509Certificate = null;
		try {

			x509Certificate = (X509Certificate) certificate;
			CertStore certStore = createCertStore(x509Certificate, timeReference, trustAnchors);


			List<OCSPResp> ocspRespList = null; // FIXME
			X509Certificate ocspServerCertificate = null; // FIXME

			CertPathValidator.validateCertPath(x509Certificate, certStore, timeReference, trustAnchors,
					revocationRequirements, ocspRespList, ocspServerCertificate, sigReport, this);

		} catch (CertificationPathException certificationPathException) {

			Throwable cause = certificationPathException.getCause();
			if (cause == null) {
				// Certificado expirado ou ainda não é válido
				result = ValidationResult.validationNotPossible;
				result.setRevocationDate(x509Certificate.getNotAfter());
				result.setMessage(certificationPathException.getMessage());
				
				CertPath certPath = certificationPathException.getCertPath();
				CertPathValidator.buildValidationDataReport(trustAnchors, sigReport, certPath);
			} else {
				messageError = cause.getMessage();
				result.setMessage(cause.getMessage());

				if (cause instanceof CertPathValidatorException) {
					CertPathValidatorException validationException = (CertPathValidatorException) cause;

					int index = validationException.getIndex();

					CertPath certPath = validationException.getCertPath();
					if (certPath != null) {
						certWithError = certPath.getCertificates().get(index);
						result = getCertPathErrorReason(cause);
					}

				} else {
					result = ValidationResult.validationNotPossible;
				}
			}
		} catch (LCRException lcrException) {
			result = ValidationResult.crlMissing;
			result.setMessage(lcrException.getMessage());
			certWithError = x509Certificate;
		} catch (Exception e) {
			result = ValidationResult.invalid;
			result.setMessage(e.getMessage());
		} catch (Throwable t) {
			result = ValidationResult.invalid;
			result.setMessage("Ocorreu um erro inesperado ao validar o caminho de certificação.");
		}

		return result;
	}

	/**
	 * Retorna o motivo do erro em uma validação de caminho de certificação
	 * @param cause A exceção que causou o erro
	 * @return O motivo do erro na validação
	 */
	private ValidationResult getCertPathErrorReason(Throwable cause) {
		ValidationResult result;
		result = ValidationResult.invalid;

		CertPathValidatorException exception = (CertPathValidatorException) cause;

		List<? extends Certificate> certs = exception.getCertPath().getCertificates();
		int index = exception.getIndex();

		certWithError = certs.get(index);

		Reason reason = exception.getReason();

		messageError = reasons.get(reason);
		result.setMessage(reasons.get(reason));

		if (reason.equals(BasicReason.UNDETERMINED_REVOCATION_STATUS)) {

			List<RevocationInformation> revList = this.vsRepository.aditionalRevocationInformation;

			RevocationInformation.CRLResult temp = null;
			int i = 0;

			while (i < revList.size() && temp == null) {
				if (certWithError != null)
					temp = revList.get(i).getCRLFromCertificate(certWithError,
							new Time(SystemTime.getSystemTime()));
				i++;
			}

			if (temp != null) {
				this.crlWithError = temp.crl;
			}

			result = getCRLInfo(this.crlWithError, (X509Certificate) certWithError);
		}

		if (reason.equals(BasicReason.REVOKED)) {

			CertificateRevokedException rev = (CertificateRevokedException) exception.getCause();
			result.setRevocationDate(rev.getRevocationDate());
			result.setRevocationCertificate(certWithError);
		}

		return result;
	}

	/**
	 * Testa as condições da CRL, para ver se esta dentro do período de
	 * validade.
	 * @param crl A crl que se deseja analisar as condições
	 * @return O resultado do teste da CRL
	 */
	private ValidationResult getCRLInfo(CRL crl, X509Certificate certificate) {

		ValidationResult result = ValidationResult.invalid;

		X509CRL crlTemp = (X509CRL) crl;

		if (crlTemp == null) {
			result = ValidationResult.validationNotPossible;
			result.setMessage(CertificationPathException.CRL_NOT_FOUND);
			return  result;
		}

		GregorianCalendar actualData = new GregorianCalendar();
		Date actual = actualData.getTime();

		Date nextUpdate = crlTemp.getNextUpdate();
		Date thisUpdate = crlTemp.getThisUpdate();

		if (nextUpdate != null && actual.after(nextUpdate)) {
			result = ValidationResult.invalidCrl;
			result.setMessage("A LCR está expirada.");
		} else if (thisUpdate != null && actual.before(thisUpdate)) {
			result = ValidationResult.invalidCrl;
			result.setMessage("A LCR ainda não é valida.");
		} else if (crlTemp.isRevoked(certificate)) {
			result = ValidationResult.invalid;
			// X509CRLEntry t = crlTemp.getRevokedCertificate(certificate);
			result.setMessage("O certificado está revogado.");
		}
		return result;
	}

	/**
	 * Cria o caminho de certificação do certificado dado, no caso do caminho ser construído corretamente, popula-se
	 * as coleções de ceritifcados utilizadas na verificação.
	 * @param certificate O certificado
	 * @param trustAnchors Conjunto de âncoras de confiança para o caminho de certificação
	 * @param timeReference Data de referência
	 * @return O caminho de certificação gerado
	 */
	public CertPath generateCertPath(Certificate certificate, Set<TrustAnchor> trustAnchors, Time timeReference) {
		
		CertPath buildPath = this.certPaths.get(certificate);
		if(buildPath != null)
			return buildPath;

		CertPath certPath = generateCertPathNoSave(certificate, trustAnchors, timeReference);
		if (certPath != null) {
			this.certPaths.put(certificate, certPath);
		}
		return certPath;
	}

	/**
	 * Cria o caminho de certificação sem o uso de armazenamento
	 *
	 * @param certificate
	 *            O certificado
	 * @param trustAnchors
	 *            TrustPoints
	 * @param timeReference
	 *            TimeReference
	 *
	 * @return CertPath O caminho de certificação.
	 */
	public CertPath generateCertPathNoSave(Certificate certificate, Set<TrustAnchor> trustAnchors, Time timeReference) {

		if (certificate == null || trustAnchors == null) {
			return null;
		}

		X509Certificate x509Certificate = (X509Certificate) certificate;

		CertStore certStore = createCertStoreVariable(x509Certificate, timeReference, trustAnchors);

		// Apenas os certificados de AC raiz são passados como âncoras de confiança
		// para a construção do caminho de certificação
		Set<TrustAnchor> trustAnchorsRoots = new HashSet<>();
		X509Certificate taCert;
		for (TrustAnchor ta : trustAnchors) {
			taCert = ta.getTrustedCert();
			if (taCert.getSubjectX500Principal().equals(taCert.getIssuerX500Principal())){
				trustAnchorsRoots.add(ta);
			}
		}

		CertPath certPath = null;
		try {
			certPath = CertPathBuilder.buildPath(x509Certificate, certStore, trustAnchorsRoots, timeReference, false);
		} catch (CertificationPathException e) {
			certPath = e.getCertPath();
			Application.logger.log(Level.WARNING,
					"Mensagem sobre o caminho de certificação: " + e.getMessage());
		} catch (NullPointerException nullPointerException) {
			Application.logger.log(Level.WARNING, "Não foi possível obter o caminho de certificação",
					nullPointerException);
		}

		if (certPath != null) {
			List<CertificateCollection> certList = this.vsRepository.aditionalCertificateCollection;
			List<X509Certificate> certificatesInPath = (List<X509Certificate>) certPath.getCertificates();

			for (CertificateCollection certificateCollection : certList) {
				certificateCollection.addCertPath(certificatesInPath);
			}
		}

		return certPath;
	}

	/**
	 * Cria o conjunto de certificados na cadeia de certificação e LCRs do certificado dado
	 * @param x509Certificate O certificado no qual será construído o {@link CertStore}
	 * @param trustAnchors O conjunto de âncoras de confiança
	 * @return O conjunto de certificados criado
	 */
	private CertStore createCertStoreVariable(X509Certificate x509Certificate, Time timeReference, Set<TrustAnchor> trustAnchors) {

		CertStore certStore = null;

		try {
			certStore = createCertStore(x509Certificate, timeReference, trustAnchors);
			if (certStore.getCRLs(new X509CRLSelector()).isEmpty()) {
				throw new LCRException(LCRException.CRL_NOT_FOUND, null);
			}
		} catch (InvalidAlgorithmParameterException e) {
			Application.logger.log(Level.WARNING, "Algoritmo inválidos.", e);
		} catch (NoSuchAlgorithmException e) {
			Application.logger.log(Level.WARNING, "Algoritmo inexistente.", e);
		} catch (LCRException e) {
			Application.logger.log(Level.SEVERE, LCRException.CRL_NOT_FOUND, e.getMessage());
		} catch (CertStoreException e) {
			Application.logger.log(Level.SEVERE, CertificationPathException
					.ERROR_WHEN_SELECTING_CRL_IN_THE_CERTSTORE);
		}

		return certStore;
	}

	/**
	 * Retorna o certificado com erro
	 * @return O certificado com erro
	 */
	@Override
	public Certificate getCertificateWithError() {
		return this.certWithError;
	}

	/**
	 * Retorna a LCR com erro
	 * @return A LCR com erro
	 */
	@Override
	public CRL getCrlWithError() {
		return this.crlWithError;
	}

	/**
	 * Retorna a mensagem de erro
	 * @return A mensagem de erro
	 */
	@Override
	public String getMessageError() {
		return this.messageError;
	}

	private boolean hasTrustAnchorAsIssuer(X509Certificate certificate, Set<TrustAnchor> trustAnchors) {
		for (TrustAnchor trustAnchor : trustAnchors) {
			X509Certificate taCertificate = trustAnchor.getTrustedCert();
			if (checkIssuer(certificate, taCertificate)) {
				return true;
			}
		}
		return false;
	}

	private boolean checkIssuer(X509Certificate certificate, X509Certificate issuer) {
		Principal issuerDN = certificate.getIssuerDN();
		Principal subjectDN = issuer.getSubjectDN();

		if (issuerDN.equals(subjectDN)) {
			try {
				// O método "verify" é void e jogará uma exceção caso haja algo de errado na verificação da assinatura do emissor.
				certificate.verify(issuer.getPublicKey());
				// (Retornará true se válido).
				return true;
			} catch (CertificateException
					| NoSuchAlgorithmException
					| InvalidKeyException
					| SignatureException
					|NoSuchProviderException ignore) { }
		}
		return false;
	}

	private boolean isSelfSignedCertificate(X509Certificate certificate) {
		return checkIssuer(certificate, certificate);
	}

	/**
	 * Cria o conjunto de certificados na cadeia de certificação e LCRs do certificado dado
	 * @param certificate O certificado que se deseja obter o caminho de certificação
	 * @param trustAnchors O conjunto de âncoras de confiança
	 * @return O conjunto de certificados
	 * @throws InvalidAlgorithmParameterException Exceção em caso de algoritmo inválido
	 * @throws NoSuchAlgorithmException Exceção em caso de algoritmo inexistente
	 * @throws LCRException Exceção caso a LCR não for encontrada
	 */
	private CertStore createCertStore(X509Certificate certificate, Time timeReference, Set<TrustAnchor> trustAnchors)
			throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, LCRException {

		CollectionCertStoreParameters certStoreParams;

		List<CertificateCollection> certList = this.vsRepository.aditionalCertificateCollection;
		List<RevocationInformation> revList = this.vsRepository.aditionalRevocationInformation;

		List<Certificate> certificateList = new ArrayList<Certificate>();
		certificateList.add(certificate);

		try {
			Certificate lastCertificate = certificate;
			Certificate issuer;
			while (!this.isSelfSignedCertificate((X509Certificate) lastCertificate) && !this.hasTrustAnchorAsIssuer((X509Certificate) lastCertificate, trustAnchors)) {
				issuer = null;
				for (int i = 0; i < certList.size() && issuer == null; i++) {
					CertificateCollection certificateCollection = certList.get(i);
					try {
						issuer = certificateCollection.getIssuerCertificate((X509Certificate) lastCertificate);
					} catch (CertificateCollectionException ignore) { }
				}
				if (issuer != null) {
					certificateList.add(issuer);
					lastCertificate = issuer;
				} else {
					throw new CertificateCollectionException(CertificateCollectionException.CERTIFICATE_NOT_FOUND);
				}
			}
			// Apesar da cadeia ser encontrada nas coleções, ainda não se tem certeza que o certificado
			// do assinante está presente. Então adiciona-se por segurança.
			for (CertificateCollection certificateCollection : certList) {
				certificateCollection.addCertificates(Collections.singletonList(certificate));
			}
		} catch (CertificateCollectionException e) {
			List<X509Certificate> certificates = new ArrayList<>();
			try {
				certificates = ValidationDataService.downloadCertChainFromAia((X509Certificate) certificate);
			} catch (AIAException e2) {
				Application.logger.log(Level.SEVERE, "Erro ao obter o AIA no supports");
			}

			certificateList.addAll(certificates);
			if (!certificates.isEmpty()) {
				for (CertificateCollection certificateCollection : certList) {
					certificateCollection.addCertificates(certificates);
				}
			}
		}

		/* Adiciona os certificados de ACs intermediárias e raiz da cadeia à lista de certificados.
		Se os certificados de ACs intermediárias do caminho de certificação estiverem em
		'trustAnchors', eles serão adicionados à 'certificateList'.
		É necessário pois a busca pelos certificados por AIA pode ter falhado e eles
		não estarão disponíveis em 'certList'.
		'trustAnchors' é formado pelos certificados buscados nos links em 'web.xml'.
		*/
		X500Principal certName, issuerName;
		X509Certificate taCert;
		X509Certificate cert = certificate;

		while (cert != null &&
				!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
			issuerName = cert.getIssuerX500Principal();
			cert = null;
			// Verifica se o issuer já está presente em 'certificateList'
			for (Certificate c : certificateList) {
				certName = ((X509Certificate) c).getSubjectX500Principal();
				if (certName.equals(issuerName)) {
					cert = ((X509Certificate) c);
					break;
				}
			}
			// Se o issuer não está presente na lista, ele é buscado no conjunto
			// de âncoras de confiança
			if (cert == null) {
				for (TrustAnchor ta : trustAnchors) {
					taCert = ta.getTrustedCert();
					if (taCert.getSubjectX500Principal().equals(issuerName)) {
						certificateList.add(taCert);
						cert = taCert;
						break;
					}
				}
			}
		}


		List<Object> params = new ArrayList<Object>(certificateList);
		params.addAll(getCRLsFromCertificates(revList, certificateList, timeReference));

		certStoreParams = new CollectionCertStoreParameters(params);

		return CertStore.getInstance("Collection", certStoreParams);

	}

	/**
	 * Busca LCRs de certificados de diferentes maneiras, de acordo com a lista
	 * de componentes (web, cache, atributos de assinatura etc.)
	 * 
	 * @param revList Componentes com métodos distintos para a obtenção das LCRs
	 * @param certificates Lista de certificados
	 * @param reference Referência de tempo, utilizada no contexto de carimbos de
	 *            tempo para selecionar a LCR correta
	 * @throws LCRException Exceção caso uma LCR válida não tenha sido obtida para um
	 *             certificado
	 */
	private List<CRL> getCRLsFromCertificates(List<RevocationInformation> revList,
			List<Certificate> certificates, Time reference) throws LCRException {

		List<CRL> crls = new ArrayList<CRL>();
		for (Certificate cert : certificates) {

			if (!containsCrl(cert, crls)) {

				CRLResult crl = null;
				for (int i = 0; i < revList.size() && crl == null; ++i) {
					crl = revList.get(i).getCRLFromCertificate(cert, reference);
				}

				if (crl != null) {
					if (!crls.contains(crl)) {
						this.addCrlResult(crl);
						crls.add(crl.crl);
					}
				}
			}
		}

		return crls;

	}

	/**
	 * Verifica se a lista de LCRs contém a LCR do certificado dado
	 * @param cert O certificado a ser utilizado na comparação
	 * @param crls A lista de LCRs
	 * @return Indica se a lista de LCRs contém a LCR do certificado dado
	 */
	private static boolean containsCrl(Certificate cert, List<CRL> crls) {

		for (CRL c : crls) {
			X509CRL x509crl = (X509CRL) c;
			X509Certificate x509Cert = (X509Certificate) cert;
			if (x509crl.getIssuerX500Principal().equals(x509Cert.getIssuerX500Principal())) {
				return true;
			}
		}

		return false;

	}

	/**
	 * Adiciona uma LCR e seu status ao mapa
	 * @param temp O resultado a ser adicionado ao mapa
	 */
	private void addCrlResult(CRLResult temp) {
		if (!this.crlCacheMap.containsKey(temp.crl)) {
			this.crlCacheMap.put(temp.crl, temp);
		}
	}

	/**
	 * Verifica se a LCR foi obtida online
	 * @param crl A LCR a ser verificada
	 * @return Indica se a LCR foi obtida online
	 */
	public boolean isCrlFromWeb(X509CRL crl) {
		return this.crlCacheMap.get(crl).fromWeb;
	}

	/**
	 * Retorna as LCR que satisfaçam a condição
	 * @param selector {@link CRLSelector} que indica a condição de busca das LCRs
	 * @return A lista de LCRs que satisfizeram a condição de busca
	 */
	@Override
	public List<X509CRL> getCRLs(X509CRLSelector selector) {
		List<X509CRL> crls = new ArrayList<X509CRL>();

		for (CRL crl : this.crlCacheMap.keySet()) {
			if (selector.match(crl))
				crls.add((X509CRL) crl);
		}

		return crls;
	}

	/**
	 * Retorna as LCR que satisfaçam a condição
	 * @param selector {@link CRLSelector} que indica a condição de busca das LCRs
	 * @param timeReference Data em que a LCR deve ser válida
	 * @return A lista de LCRs que satisfizeram a condição de busca
	 */
	@Override
	public List<X509CRL> getCRLs(X509CRLSelector selector, Time timeReference) {
		Set<X509CRL> crlsRet = new HashSet<X509CRL>();

		for (CRL crl : this.crlCacheMap.keySet()) {
			if (selector.match(crl)) {
				X509CRL xCrl = (X509CRL) crl;
				if (xCrl.getNextUpdate().after(timeReference) && xCrl.getThisUpdate().before(timeReference))
					crlsRet.add(xCrl);
			}
		}

		return new ArrayList<>(crlsRet);
	}

}
