package br.ufsc.labsec.signature.conformanceVerifier.cades;

import java.io.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CRL;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.*;
import java.util.logging.Level;

import javax.security.auth.x500.X500Principal;

import br.ufsc.labsec.signature.*;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.ValidationDataService;
import br.ufsc.labsec.signature.signer.signatureSwitch.SignatureDataWrapperGenerator;
import br.ufsc.labsec.signature.signer.signatureSwitch.SwitchHelper;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.io.Streams;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.SignaturePolicyInterface.AdESType;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SigningCertificateInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificate;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificateV2;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.CadesSignatureException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignerException;
import br.ufsc.labsec.signature.exceptions.AIAException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe trata as partes em comum entre assinaturas CAdES e
 * carimbos do tempo.
 */
public abstract class AbstractCadesSigner extends SignatureDataWrapperGenerator {

	private PrivateKey privateKey;

	/**
	 * Gerenciador de atributos
	 */
	protected CadesAttributeIncluder attributeIncluder;
	/**
	 * Assinatura CAdES
	 */
	protected Signature signature;
	/**
	 * Gerador de container de assinatura
	 */
	protected SignatureContainerGenerator signatureContainerGenerator;
	/**
	 * Container de assinatura
	 */
	protected SignatureContainer signatureContainer;

	/**
	 * Construtor
	 * @param cadesSignature Componente de assinatura CAdES
	 */
	public AbstractCadesSigner(CadesSignatureComponent cadesSignature) {
		this.attributeIncluder = new CadesAttributeIncluder();
		this.attributeIncluder.setCadesSignature(cadesSignature);
	}

	/**
	 * Atribui os valores de chave privada e certificado do assinante para a realização da assinatura
	 * @param keyStore {@link KeyStore} que contém as informações do assinante
	 * @param password Senha do {@link KeyStore}
	 */
	public void selectInformation(KeyStore keyStore, String password) {
		String alias = SwitchHelper.getAlias(keyStore);
		Certificate certificate = SwitchHelper.getCertificate(keyStore, alias);
		PrivateKey privateKey = SwitchHelper.getPrivateKey(keyStore, alias, password.toCharArray());
		selectInformation(new SimplePrivateInformation(certificate, privateKey));
	}

	/**
	 * Atribui os valores de chave privada e certificado do assinante para a realização da assinatura
	 * @param privateInformation {@link PrivateInformation} que contém as informações do assinante
	 */
	public void selectInformation(PrivateInformation privateInformation) {
		attributeIncluder.getCadesSignature().privateInformation = privateInformation;
		attributeIncluder.setSignerCertificate(privateInformation.getCertificate());
		attributeIncluder.setTrustAnchors(this.getSignaturePolicyInterface().getSigningTrustAnchors());
	}

	/**
	 * Retorna a lista de atributos assinados obrigatórios da assinatura
	 * @return A lista de atributos assinados obrigatórios da assinatura
	 */
	public List<String> getMandatedSignedAttributeList() {
		List<String> mandatedAttributes = new ArrayList<>();
		for (String attributeOid : this.attributeIncluder.getCadesSignature().signaturePolicyInterface
				.getMandatedSignedAttributeList()) {
			mandatedAttributes.add(AttributeFactory.translateOid(attributeOid));
		}

		return mandatedAttributes;
	}

	/**
	 * Retorna o container d de assinatura
	 */
	public SignatureContainer getSignature() {
		return this.attributeIncluder.getSignatureContainer();
	}

	/**
	 * Adiciona um atributo à assinatura
	 * @param attribute O atributo a ser selecionado
	 */
	public void selectAttribute(String attribute) {
		if (!attributeIncluder.getSelectedAttributes().contains(attribute.trim())) {
			attributeIncluder.getSelectedAttributes().add(attribute.trim());
		}

	}

	/**
	 * Retora o componente de assinatura CAdES
	 * @return O componente de assinatura CAdES
	 */
	public CadesSignatureComponent getComponent() {
		return this.attributeIncluder.getCadesSignature();
	}

	/**
	 * Remove um atributo da assinatura
	 * @param attribute O atributo a ser removido
	 */
	public void unselectAttribute(String attribute) {
		if (attributeIncluder.getSelectedAttributes().contains(attribute)) {
			attributeIncluder.getSelectedAttributes().remove(attribute);
		}
	}

	/**
	 * Retorna a lista de políticas de assinatura disponiveis
	 * @return A lista de políticas de assinatura
	 */
	public List<String> getPoliciesAvailable() {
		return this.attributeIncluder.getCadesSignature().signaturePolicyInterface
				.getPoliciesAvaiable(AdESType.CAdES);
	}

	/**
	 * Retorna a lista de atributos assinados disponíveis para a assinatura
	 * @return A lista de atributos assinados disponíveis para a assinatura
	 */
	public List<String> getSignedAttributesAvailable() {
		List<String> attributesAvailable = new ArrayList<String>();

		attributesAvailable.add(AttributeFactory.id_aa_ets_signerLocation);
		attributesAvailable.add(AttributeFactory.id_contentType);
		attributesAvailable.add(AttributeFactory.id_aa_contentHint);
		attributesAvailable.add(AttributeFactory.id_signingTime);
		attributesAvailable.add(AttributeFactory.id_messageDigest);
		attributesAvailable.add(AttributeFactory.id_aa_signingCertificate);

		return attributesAvailable;
	}

	/**
	 * Retorna a lista de atributos não-assinados disponíveis para a assinatura
	 * @return A lista de atributos não-assinados disponíveis para a assinatura
	 */
	public List<String> getUnsignedAttributesAvailable() {
		List<String> attributesAvailable = new ArrayList<>();

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
	 * Retorna os bytes do arquivo indicado
	 * @param filePath O endereço do arquivo
	 * @return Os bytes do arquivo
	 */
	protected byte[] getFileBytes(String filePath) {
		File file = new File(filePath);
		FileInputStream inputStream = null;
		try {
			inputStream = new FileInputStream(file);
		} catch (FileNotFoundException e) {
			Application.logger.log(Level.SEVERE, "Arquivo não encontrado.", e);
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
	 * Realiza a assinatura
	 * @param error Indica se ouve algum erro na geração da assinatura
	 * @param unsignedAttributesList Lista de atributos não assinados
	 * @param signatureContainerGenerator Gerador de container de assinatura
	 * @return Indica se a assinatura foi gerada com sucesso
	 */
	protected final boolean doSign(boolean error, List<String> unsignedAttributesList,
			SignatureContainerGenerator signatureContainerGenerator) {
		
		
		PrivateKey privateKey = this.attributeIncluder.getCadesSignature().privateInformation.getPrivateKey();

		X509Certificate signerCertificate = this.attributeIncluder.getCadesSignature().privateInformation.getCertificate();
		this.attributeIncluder.setSignerCertificate(signerCertificate);
		this.attributeIncluder.setTrustAnchors(this.getSignaturePolicyInterface().getSigningTrustAnchors());

		SignerData signer;
		try {
			signer = new SignerData(signerCertificate, privateKey);
		} catch (Exception e) {
			Application.logger.log(Level.SEVERE, e.getMessage(), e);
			return false;
		}

		try {
			 List<X509Certificate> certificates = ValidationDataService.downloadCertChainFromAia(signerCertificate);
			 this.attributeIncluder.getCadesSignature().getSignatureIdentityInformation().addCertificates(certificates);
		} catch (AIAException e1) {}
		
		AttributeFactory attributeFactory = new AttributeFactory(this.attributeIncluder);

		this.attributeIncluder.getSelectedAttributes().remove(AttributeFactory.id_aa_ets_sigPolicyId);

		Iterator<String> selectedAttributesIterator = this.attributeIncluder.getSelectedAttributes().iterator();

		while (!error && selectedAttributesIterator.hasNext()) {
			String nextAttribute = selectedAttributesIterator.next();
			if (attributeFactory.isSigned(nextAttribute)) {
				SignatureAttribute attribute;
				try {
					attribute = attributeFactory.getAttribute(nextAttribute);
				} catch (Exception e) {
					Application.logger.log(Level.SEVERE, e.getMessage(), e);
					return false;
				}
				if (attribute != null) {
					signatureContainerGenerator.addAttribute(attribute);
				}
			} else {
				unsignedAttributesList.add(nextAttribute);
			}
		}

		/* Atributos Comuns */
		try {
			this.buildBasicSignature(signer, signatureContainerGenerator);
		} catch (SignerException e) {
			Application.logger.log(Level.SEVERE,
					"Ocorreu um erro referente ao certificado do assinante ou a chave privada do assinante", e);
			error = true;
		}
		if (error) {
			return false;
		}

		/* Assinatura */
		try {
			// this.attributeIncluder.setSignatureContainer((CadesSignatureContainer)
			// signatureContainerGenerator
			// .sign());

			/* Assinatura */
			this.signature = this.sign(signatureContainerGenerator);
			if (this.signature == null) {
				return false;
			}
			this.attributeIncluder.setSignature(signature);

			if (signature == null) {
				return false;
			}

			for (String unsignedOptionalAttribute : unsignedAttributesList) {
				if (!unsignedOptionalAttribute.trim().equals(AttributeFactory.id_aa_ets_escTimeStamp)
						&& !unsignedOptionalAttribute.trim().equals(AttributeFactory.id_aa_ets_archiveTimeStampV2)) {
					if (!this.signature.getAttributeList().contains(unsignedOptionalAttribute.trim())) {
						SignatureAttribute attribute = attributeFactory.getAttribute(unsignedOptionalAttribute.trim());
						if (attribute == null)
							return false;
						this.signature.addUnsignedAttribute(attribute);
					}
				}
			}

			if (unsignedAttributesList.contains(AttributeFactory.id_aa_ets_escTimeStamp)) {
				SignatureAttribute attribute = attributeFactory.getAttribute(AttributeFactory.id_aa_ets_escTimeStamp);
				if (attribute == null)
					return false;
				this.signature.addUnsignedAttribute(attribute);
			}

			if (unsignedAttributesList.contains(AttributeFactory.id_aa_ets_archiveTimeStampV2)) {
				SignatureAttribute attribute = attributeFactory
						.getAttribute(AttributeFactory.id_aa_ets_archiveTimeStampV2);
				if (attribute == null)
					return false;
				this.signature.addUnsignedAttribute(attribute);
			}

		} catch (Exception e) {
			Application.logger.log(Level.SEVERE, e.getMessage(), e);
			return false;
		}

		return true;
	}

	/**
	 * Salva a assinatura gerada em formato .p7s
	 * @return Indica se a assinatura foi salva com sucesso
	 */
	public boolean saveSignature(String type) throws EncodingException {
		OutputStream outputStream = this.attributeIncluder.getCadesSignature().ioService.save(type);

		CadesSignatureContainer sig = attributeIncluder.getSignatureContainer();
		
		if (outputStream != null && sig != null) {
			sig.encode(outputStream);
		} else {
			return false;
		}
		return true;
		
	}

	/**
	 * Realiza a assinatura
	 * @return {@link Signature} que contém a assinatura gerada
	 */
	protected Signature sign(SignatureContainerGenerator signatureContainerGenerator) throws CadesSignatureException {
		try {
			this.signatureContainer = signatureContainerGenerator.sign();
			attributeIncluder.setSignatureContainer(this.signatureContainer);
			return this.signatureContainer.getSignatureAt(0);
		} catch (PbadException e) {
			Application.logger.log(Level.SEVERE, e.getMessage(), e);
		}
		return null;
	}

	/**
	 * Retorna a lista de atributos não assinados obrigatórios da assinatura
	 * @return A lista de atributos não assinados obrigatórios da assinatura
	 */
	public List<String> getMandatedUnsignedAttributeList() {
		List<String> mandatedAttributes = new ArrayList<String>();
		for (String attributeOid : this.attributeIncluder.getCadesSignature().signaturePolicyInterface
				.getMandatedUnsignedSignerAttributeList()) {
			mandatedAttributes.add(AttributeFactory.translateOid(attributeOid));
		}

		return mandatedAttributes;
	}

	/**
	 * Retorna a política de assinatura
	 * @return A política de assinatura
	 */
	public SignaturePolicyInterface getSignaturePolicyInterface() {
		return this.attributeIncluder.getCadesSignature().signaturePolicyInterface;
	}

	/**
	 * Inicializa as informações do assinante
	 * @param signer O assinante
	 * @param signatureContainerGenerator Gerador de container de assinatura
	 * @throws SignerException Exceção em caso de erro no assinante
	 */
	private void buildBasicSignature(SignerData signer, SignatureContainerGenerator signatureContainerGenerator)
			throws SignerException {
		/* Signatário */
		// X509Certificate signerCertificate =
		// certManager.getSignerCertificate();

		signatureContainerGenerator.setSigner(signer);

	}

	/**
	 * Adiciona novos atributos a um carimbo de tempo. Os atributos são adicionados como
	 * não-assinados
	 * @param timeStamp Os bytes do carimbo de tempo
	 * @param attributesList A lista de atributos a serem adicionados no carimbo
	 * @return Os bytes do carimbo com os atributos adicionados
	 */
	public byte[] addAttributesTimeStamp(byte[] timeStamp, List<String> attributesList) {
		ContentInfo contentInfo = null;
		byte[] resultingContentInfo = null;
		try {
			contentInfo = ContentInfo.getInstance((ASN1Sequence) ASN1Sequence.fromByteArray(timeStamp));
			CMSSignedData cmsSignedData = new CMSSignedData(contentInfo);
			CadesSignatureContainer container = new CadesSignatureContainer(cmsSignedData);
			CadesSignature signature = null;
			signature = container.getSignatureAt(0);
			this.attributeIncluder.setSignature(signature);

			X509Certificate signingCertificate = this.getSignerCertificate(signature);
			this.attributeIncluder.setSignerCertificate(signingCertificate);
			this.attributeIncluder.setTrustAnchors(this.getSignaturePolicyInterface().getTimeStampTrustAnchors());
			List<X509Certificate> aiaCertificates = ValidationDataService.downloadCertChainFromAia(signingCertificate);
			this.attributeIncluder.getCadesSignature().certificateCollection.get(0).addCertificates(aiaCertificates);
			
			AttributeFactory attributeFactory = new AttributeFactory(this.attributeIncluder);

			for (String attributeName : attributesList) {
				SignatureAttribute signatureAttribute = attributeFactory.getAttribute(attributeName);
				signature.addUnsignedAttribute(signatureAttribute);
			}
			contentInfo = container.getSignedData().toASN1Structure();
			resultingContentInfo = contentInfo.getEncoded();
		} catch (Exception e) {
			Application.logger.log(Level.SEVERE, e.getMessage(), e);
		}

		return resultingContentInfo;
	}

	/**
	 * Retorna o certificado do assinante do carimbo de tempo dado
	 * @param timeStamp O carimbo de tempo
	 * @return O certificado do assinante do carimbo
	 */
	private X509Certificate getSignerCertificate(CadesSignature timeStamp) throws CertificateException, IOException,
			SignatureAttributeException {
		List<X509Certificate> certificates = timeStamp.getCertificates();
		if (certificates != null && certificates.size() > 0) {
			return timeStamp.getSigningCertificate();
		}

		List<String> attributeList = timeStamp.getAttributeList();
		SigningCertificateInterface signingCertificateInterface = null;
		if (attributeList.contains(IdAaSigningCertificate.IDENTIFIER)) {
			signingCertificateInterface = new IdAaSigningCertificate(
					timeStamp.getEncodedAttribute(IdAaSigningCertificate.IDENTIFIER));
		} else {
			signingCertificateInterface = new IdAaSigningCertificateV2(
					timeStamp.getEncodedAttribute(IdAaSigningCertificateV2.IDENTIFIER));
		}
		
		int i = 0;
		Certificate certTemp = null;
		List<CertificateCollection> certs = this.attributeIncluder.getCadesSignature().certificateCollection;
		
		while(certTemp == null && i < certs.size()) {
			certTemp = certs.get(i).getCertificate(signingCertificateInterface);
			i++;
		}

		return (X509Certificate) certTemp;
	}

	/**
	 * Retorna uma lista de atributos não assinados de carimbo de tempo
	 * @return Lista de atributos não assinados de carimbo de tempo
	 */
	public List<String> getUnsignedAttributesForTimeStamp() {
		AttributeFactory attributeFactory = new AttributeFactory(this.attributeIncluder);

		List<String> timeStamps = new ArrayList<>();
		timeStamps.add(AttributeFactory.id_aa_ets_archiveTimeStampV2);
		timeStamps.add(AttributeFactory.id_aa_ets_escTimeStamp);
		timeStamps.add(AttributeFactory.id_aa_signatureTimeStamp);

		List<String> atts = new ArrayList<>();

		for (String optionalAttribute : attributeIncluder.getSelectedAttributes()) {

			if (!attributeFactory.isSigned(optionalAttribute) && !timeStamps.contains(optionalAttribute)) {
				atts.add(optionalAttribute);
			}
		}

		return atts;
	}

	/**
	 * Retorna todos os certificados do caminho de certificação mais o
	 * certificado da âncora de confiança correspondente a este caminho.
	 * @param certPath Os certificados no caminho de certificação
	 * @return Uma nova lista com os certificados do caminho e da âncora de confiança
	 */
	public List<X509Certificate> addTrustAnchor(List<X509Certificate> certPath) {
		X509Certificate lastIntermediateCA = certPath.get(certPath.size() - 1);
		X500Principal trustPointIssuer = lastIntermediateCA.getIssuerX500Principal();
		X509Certificate trustPoint = (X509Certificate) this.attributeIncluder.getCadesSignature().signaturePolicyInterface
				.getTrustPoint(trustPointIssuer).getTrustPoint();
		List<X509Certificate> certificates = new ArrayList<X509Certificate>(certPath);
		certificates.add(trustPoint);
		return certificates;
	}

	/**
	 * Retorna os certificados do caminho de certificação do assinante e o
	 * certificado da âncora de confiança correspondente
	 * @return Lista com os certificados do caminho de certificação e o
	 * certificado da âncora de confiança
	 */
	public List<X509Certificate> getCertificateReferences() {
		X509Certificate signCert = this.attributeIncluder.getCadesSignature().privateInformation.getCertificate();

		List<X509Certificate> signCertPath = (List<X509Certificate>) this.getCertPath(signCert).getCertificates();
		signCertPath = this.addTrustAnchor(signCertPath);
		return signCertPath;
	}

	/**
	 * Retorna o caminho de certificação do certificado dado
	 * @param cert O certificado
	 * @return O caminho de certificação do certificado
	 */
	public CertPath getCertPath(X509Certificate cert) {

		return this.attributeIncluder.getCadesSignature().certificateValidation.generateCertPath(cert,
				this.attributeIncluder.getCadesSignature().signaturePolicyInterface.getSigningTrustAnchors(), new Time(
						SystemTime.getSystemTime()));
	}

	/**
	 * Retorna a Lista de Certificados Revogados dos certificados
	 * do caminho de certificação do certificado do assinante
	 * @return a Lista de Certificados Revogados dos certificados
	 * do caminho de certificação
	 */
	public List<X509CRL> getCRLs() {

		List<X509Certificate> signCertPath = getCertificateReferences();
		List<X509CRL> crls = new ArrayList<>();

		for (X509Certificate x509Certificate : signCertPath) {
			
			int i = 0;
			CRL crlTemp = null;
			List<RevocationInformation> crlList = this.attributeIncluder.getCadesSignature().revocationInformation;
			
			while(i < crls.size()) {
				crlTemp = crlList.get(i).getCRLFromCertificate(x509Certificate).crl;
				if(crlTemp != null) {
					if(!crls.contains((X509CRL) crlTemp))
						crls.add((X509CRL) crlTemp);
				}
					
				i++;
			}
			
		}
		return crls;
	}

	/**
	 * Retorna o certificado do assinante
	 * @return O certificado do assinante
	 */
	public X509Certificate getCertificate() {
		return this.attributeIncluder.getCadesSignature().privateInformation.getCertificate();
	}

	/**
	 * Retorna o valor de hash do conteúdo assinado
	 * @return O hash do conteúdo assinado
	 */
	public byte[] getSignedContentHash() throws NoSuchAlgorithmException, IOException {
		String policyHashAlgorithm = this.attributeIncluder.getCadesSignature().signaturePolicyInterface
				.getHashAlgorithmId();
		byte[] content = null;
		byte[] messageDigest = null;
		content = Streams.readAll(attributeIncluder.getContent());
		messageDigest = this.getMessageDigest(content,
				AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(policyHashAlgorithm));
		return messageDigest;
	}

	/**
	 * Calcula o valor de hash do conteúdo
	 * @param content O conteúdo
	 * @param hashAlgorithmName O algoritmo a ser utilizado no cálculo
	 * @return O valor de hash do conteúdo
	 * @throws NoSuchAlgorithmException Exceção caso o algoritmo não seja válido
	 */
	private byte[] getMessageDigest(byte[] content, String hashAlgorithmName) throws NoSuchAlgorithmException,
			IOException {
		MessageDigest digester = MessageDigest.getInstance(hashAlgorithmName);
		digester.update(content);
		return digester.digest();
	}

}