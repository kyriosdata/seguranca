package br.ufsc.labsec.signature.conformanceVerifier.cades;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.*;
import br.ufsc.labsec.signature.SignatureDataWrapper;
import br.ufsc.labsec.signature.SignaturePolicyInterface.AdESType;
import br.ufsc.labsec.signature.Signer;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.ValidationDataService;
import br.ufsc.labsec.signature.exceptions.AIAException;
import br.ufsc.labsec.signature.tsa.TimeStampAttributeIncluder;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaEtsSigPolicyId;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignerException;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignerRules.ExternalSignedData;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.CertificationPathException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.signer.FileFormat;
import br.ufsc.labsec.signature.signer.SignerType;

import java.io.*;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;

/**
 * Esta classe cria uma assinatura CAdES em um documento.
 * Estende {@link AbstractCadesSigner} e implementa {@link Signer} e {@link TimeStampAttributeIncluder}.
 */
public class CadesSigner extends AbstractCadesSigner implements Signer, TimeStampAttributeIncluder {
	/**
	 * Modo da assinatura
	 */
	private SignatureModeCAdES mode;
	/**
	 * Suite da assinatura
	 */
	private String suite;

	/**
	 * Construtor
	 * @param cadesSignature Componente de assinatura CAdES
	 */
	public CadesSigner(CadesSignatureComponent cadesSignature) {
		super(cadesSignature);
	}

	/**
	 * Inicializa o gerador de contêiner de assinatura
	 * @param target  Endereço do arquivo a ser assinado
	 * @param policy OID da política de assinatura usada
	 */
	@Override
	public SignatureDataWrapper getSignature(String filename, InputStream target, SignerType policy) {
		selectTarget(target, policy.toString());
		if (sign()) {
			InputStream stream = getSignatureStream();
			SignatureDataWrapper signature;
			if (this.mode == SignatureModeCAdES.DETACHED) {
				signature = new SignatureDataWrapper(target, stream, filename);
			} else {
				signature = new SignatureDataWrapper(stream, null, filename);
			}
			return signature;
		}
		return null;
	}

	@Override
	public void selectTarget(String target, String policyOid) {
		try {
			this.selectTarget(new FileInputStream(target), policyOid);
		} catch (FileNotFoundException e) {
			Application.logger.log(Level.SEVERE, "Arquivo não encontrado.", e);
			return;
		}

		try {
			this.attributeIncluder.setMimeType(MimeTypesMap.getInstance()
					.getContentType(new File(target)));
		} catch (FileNotFoundException e) {
			Application.logger.log(Level.SEVERE,
							"Não foi possível inicializar o detector de tipos MIME.",
							e);
		}

	}

	/**
	 * Inicializa o gerador de contêiner de assinatura
	 * @param target O arquivo que será assinado
	 * @param policyOid OID da política de assinatura utilizada
	 */
	@Override
	public void selectTarget(InputStream target, String policyOid) {
		SignerType signerType = SignerType.fromString(policyOid);
		AdESType policyType = null;
		if (signerType.isCAdES()) {
			policyType = AdESType.CAdES;
		} else if (signerType.isPAdES()) {
			policyType = AdESType.PAdES;
		}
		if (policyType == null || policyType == AdESType.CAdES) {
			this.attributeIncluder.getCadesSignature().signaturePolicyInterface
					.setActualPolicy(policyOid, null, AdESType.CAdES);
		}
		this.attributeIncluder.setTrustAnchors(
				this.attributeIncluder.getCadesSignature().signaturePolicyInterface.getSigningTrustAnchors()
		);
		this.attributeIncluder.setContent(target);
		// FIXME(mauricio): will need mimeType here if not set!!!
		this.attributeIncluder.setSelectedAttributes(new ArrayList<String>());
		this.attributeIncluder.getSelectedAttributes().addAll(
				this.getMandatedSignedAttributeList());
		this.attributeIncluder.getSelectedAttributes().addAll(
				this.getMandatedUnsignedAttributeList());
	}

	/**
	 * Realiza a assinatura
	 * @return Indica se o processo de assinatura foi concluído com sucesso
	 */
	@Override
	public boolean sign() {
		boolean error = false;
		List<String> unsignedAttributesList = new ArrayList<>();

		String policyId = this.attributeIncluder.getCadesSignature().signaturePolicyInterface.getPolicyId();
		byte[] policyHash = this.attributeIncluder.getCadesSignature().signaturePolicyInterface.getSignPolicyHash();

		String[] policyHashAlgorithms = this.attributeIncluder.getCadesSignature().signaturePolicyInterface.getHashAlgorithmIdSet();
		boolean suiteInPolicy = false;
		for (int i = 0; i < policyHashAlgorithms.length && !suiteInPolicy; i++) {
			String hashAlgorithm = policyHashAlgorithms[i];
			suiteInPolicy = hashAlgorithm.equals(suite);
		}
		if (!suiteInPolicy) {
			return false;
		}

		String policyURL = this.attributeIncluder.getCadesSignature().signaturePolicyInterface
				.getURL(AdESType.CAdES);

		IdAaEtsSigPolicyId sigPolicyId = new IdAaEtsSigPolicyId(policyId, suite, policyHash, policyURL);

		SignatureContainerGenerator signatureContainerGenerator = new SignatureContainerGenerator(
				sigPolicyId, this.attributeIncluder.getCadesSignature());

		CadesContentToBeSigned contentToBeSigned = new CadesContentToBeSigned(this.attributeIncluder.getContent(), this.mode);
		this.attributeIncluder.setContentToBeSigned(contentToBeSigned);
		signatureContainerGenerator.addContentToBeSigned(contentToBeSigned);
		

		return doSign(error, unsignedAttributesList,signatureContainerGenerator);
	}

	/**
	 * Retorna a lista dos modos de assinatura disponíveis
	 * @return Lista dos modos de assinatura disponíveis
	 */
	@Override
	public List<String> getAvailableModes() {
		List<String> availableModes = new ArrayList<String>();
		ExternalSignedData availableMode = this.attributeIncluder
				.getCadesSignature().signaturePolicyInterface
				.getExternalSignedData();
		if (availableMode.name().equals(ExternalSignedData.EXTERNAL.name())) {
			availableModes.add("Destacada");
		}
		if (availableMode.name().equals(ExternalSignedData.INTERNAL.name())) {
			availableModes.add("Anexada");
		}
		if (availableMode.name().equals(ExternalSignedData.EITHER.name())) {
			availableModes.add("Destacada");
			availableModes.add("Anexada");
		}

		return availableModes;
	}

	/**
	 * Atribue o modo de assinatura, anexada ou destacada
	 * @param mode O modo da assinatura
	 */
	@Override
	public void setMode(FileFormat mode, String suite) {
		if (mode.equals(FileFormat.DETACHED)) {
			this.mode = SignatureModeCAdES.DETACHED;
		}
		if (mode.equals(FileFormat.ATTACHED)) {
			this.mode = SignatureModeCAdES.ATTACHED;
		}
		this.suite = suite;
	}

	@Override
	public boolean supports(InputStream target, SignerType signerType) throws CertificationPathException, SignerException {
		Certificate certificate = attributeIncluder.getCadesSignature().privateInformation.getCertificate();
		SignaturePolicyInterface signaturePolicyInterface = attributeIncluder.getComponent().signaturePolicyInterface;
		CertificateValidation certificateValidation = attributeIncluder.getComponent().certificateValidation;
		Set<TrustAnchor> trustAnchors = signaturePolicyInterface.getSigningTrustAnchors();

		CertPath certPath = certificateValidation.generateCertPath(certificate, trustAnchors, new Time(SystemTime.getSystemTime()));
		if (certPath == null) {
			throw new CertificationPathException(CertificationPathException.NULL_CERT_PATH);
		}
		return true;
	}

	/**
	 * Retorna a lista de atributos disponíveis da assinatura
	 * @return A lista de atributos disponíveis da assinatura
	 */
	@Override
	public List<String> getAttributesAvailable() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * Retorna o arquivo assinado
	 * @return O {@link InputStream} do arquivo assinado
	 */
	@Override
	public InputStream getSignatureStream() {

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		InputStream is = null;

		try {
			signatureContainer.encode(outputStream);
			byte[] sigBytes = outputStream.toByteArray();

			is = new ByteArrayInputStream(sigBytes);
		} catch (EncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}


		return is;
	}

	/**
	 * Salva a assinatura gerada em formato .p7s
	 * @return Indica se a assinatura foi salva com sucesso
	 */
	@Override
	public boolean save() {
		try {
			return saveSignature("p7s");
		} catch (EncodingException e) {
			Application.logger.log(Level.SEVERE, "Não foi possível salvar a assinatura", e);
		}
		return false;
	}

}
