package br.ufsc.labsec.signature.conformanceVerifier.cades;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.CertPath;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import javax.security.auth.x500.X500Principal;

import br.ufsc.labsec.signature.SystemTime;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.util.io.Streams;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.RevocationInformation;
import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.ValidationDataService;
import br.ufsc.labsec.signature.exceptions.AIAException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;
import java.security.cert.*;
import java.util.*;

/**
 * Esta classe gerencia os atributos de uma assinatura CAdES quando a assinatura está sendo gerada.
 */
public class CadesAttributeIncluder {
	/**
	 * Componente de assinatura CAdES
	 */
	private CadesSignatureComponent cadesSignature;
	/**
	 * Conteúdo assinado
	 */
	private InputStream content;
	/**
	 * Atributos selecionados para a assinatura
	 */
	private List<String> selectedAttributes;
	/**
	 * Contêiner de assinatura CAdES
	 */
	private CadesSignatureContainer signatureContainer;
	/**
	 * Assinatura CAdES
	 */
	private Signature signature;
	/**
	 * Conteúdo a ser assinado
	 */
	private CadesContentToBeSigned contentToBeSigned;
	/**
	 * Certificado do assinante
	 */
	private X509Certificate signerCertificate;
	/**
	 * O MIME type do conteúdo a ser assinado
	 */
	private String mimeType;
	private Set<TrustAnchor> trustAnchors;

	/**
	 * Construtor
	 */
	public CadesAttributeIncluder() {
		this.selectedAttributes = new ArrayList<String>();
	}

	/**
	 * Retorna o componente de assinatura CAdES
	 * @return O componente de assinatura CAdES
	 */
	public CadesSignatureComponent getCadesSignature() {
		return cadesSignature;
	}

	/**
	 * Atribue o componente de assinatura CAdES
	 * @param cadesSignature O componente de assinatura CAdES
	 */
	public void setCadesSignature(CadesSignatureComponent cadesSignature) {
		this.cadesSignature = cadesSignature;
	}

	/**
	 * Retorna o conteúdo a ser assinado
	 * @return O conteúdo a ser assinado
	 */
	public InputStream getContent() {
		return content;
	}

	/**
	 * Atribue o MIME type do conteúdo a ser assinado
	 * @param mimeType O MIME type do conteúdo a ser assinado
	 */
	public void setMimeType(String mimeType) {
		this.mimeType = mimeType;
	}

	/**
	 * Atribue o valor do conteúdo assinado
	 * @param contentFile O conteúdo assinado
	 */
	public void setContent(InputStream contentFile) {
		this.content = contentFile;
	}

	/**
	 * Retorna os atributos selecionados
	 * @return Os atributos selecionados
	 */
	public List<String> getSelectedAttributes() {
		return selectedAttributes;
	}

	/**
	 * Atribue os atributos selecionados
	 * @param selectedAttributes Os atributos selecionados
	 */
	public void setSelectedAttributes(List<String> selectedAttributes) {
		this.selectedAttributes = selectedAttributes;
	}

	/**
	 * Retorna o valor de hash do conteúdo assinado
	 * @return O hash do conteúdo assinado
	 */
	public byte[] getSignedContentHash() throws NoSuchAlgorithmException,
			IOException {
		String policyHashAlgorithm = this.getCadesSignature().signaturePolicyInterface
				.getHashAlgorithmId();
		byte[] content = null;
		byte[] messageDigest = null;
		if (this.getContent() != null) { // Se não temos um content file
											// significa que estamos
											// contra-assinando
			content = Streams.readAll(this.getContent());
		} else {
			content = this.contentToBeSigned.getContentToBeSigned();
		}
		messageDigest = this.getMessageDigest(content,
				AlgorithmIdentifierMapper
						.getAlgorithmNameFromIdentifier(policyHashAlgorithm));
		return messageDigest;
	}

	/**
	 * Retorna o contêiner de assinatura CAdES
	 * @return O contêiner de assinatura CAdES
	 */
	public CadesSignatureContainer getSignatureContainer() {
		return signatureContainer;
	}

	/**
	 * Calcula o valor de hash do conteúdo assinado
	 * @param content O conteúdo
	 * @param hashAlgorithmName O algoritmo a ser utilizado no cálculo
	 * @return O valor de hash do conteúdo
	 * @throws NoSuchAlgorithmException Exceção caso o algoritmo não seja válido
	 */
	private byte[] getMessageDigest(byte[] content, String hashAlgorithmName)
			throws NoSuchAlgorithmException, IOException {
		MessageDigest digester = MessageDigest.getInstance(hashAlgorithmName);
		digester.update(content);
		return digester.digest();
	}

	/**
	 * Retora o componente de assinatura CAdES
	 * @return O componente de assinatura CAdES
	 */
	public CadesSignatureComponent getComponent() {
		return this.getCadesSignature();
	}

	/**
	 * Retorna a política de assinatura
	 * @return A política de assinatura
	 */
	public SignaturePolicyInterface getSignaturePolicyInterface() {
		return this.getCadesSignature().signaturePolicyInterface;
	}

	/**
	 * Retorna os certificados do caminho de certificação e o
	 * certificado da âncora de confiança correspondente
	 * @return Lista com os certificados do caminho de certificação e o
	 * certificado da âncora de confiança
	 */
	public List<X509Certificate> getCertificateReferences() {
		X509Certificate signCert = this.getSignerCertificate();
		List<X509Certificate> signCertPath = (List<X509Certificate>) this.getCertPath(signCert).getCertificates();
		signCertPath = this.addTrustAnchor(signCertPath);
		return signCertPath;
	}

	/**
	 * Retorna o certificado do assinante
	 * @return O certificado do assinante
	 */
	public X509Certificate getSignerCertificate() {
		return this.signerCertificate;
	}

	/**
	 * Atribue o certificado do assinante
	 * @param signerCertificate O certificado do assinante
	 */
	public void setSignerCertificate(X509Certificate signerCertificate) {
		this.signerCertificate = signerCertificate;
	}

	/**
	 * Adiciona uma âncora de confiança à lista de certificados
	 * do caminho de certificação
	 * @param certPath Lista com certificados do caminho de certificação
	 * @return Uma nova lista com o conteúdo da lista dada e com o certificado
	 * da âncora de confiança adicionada
	 */
	public List<X509Certificate> addTrustAnchor(List<X509Certificate> certPath) {
		X509Certificate lastIntermediateCA = certPath.get(certPath.size() - 1);
		X500Principal trustPointIssuer = lastIntermediateCA
				.getIssuerX500Principal();
		X509Certificate trustPoint = (X509Certificate) this.getCadesSignature().signaturePolicyInterface
				.getTrustPoint(trustPointIssuer).getTrustPoint();
		List<X509Certificate> certificates = new ArrayList<X509Certificate>(
				certPath);
		certificates.add(trustPoint);
		return certificates;
	}

	/**
	 * Retorna o caminho de certificação do certificado dado
	 * @param cert O certificado usado para gerar o caminho de certificação
	 * @return O caminho de certificação do certificado dado
	 */
	public CertPath getCertPath(X509Certificate cert) {
		return this.getCadesSignature().certificateValidation.generateCertPath(
				cert, this.getCadesSignature().signaturePolicyInterface
						.getSigningTrustAnchors(), new Time(SystemTime.getSystemTime()));
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
			List<RevocationInformation> crlList = this.getCadesSignature().revocationInformation;
			
			while(i < crlList.size()) {
				crlTemp = crlList.get(i).getCRLFromCertificate(x509Certificate).crl;
				if(crlTemp != null)
					if(!crls.contains((X509CRL) crlTemp))
						crls.add((X509CRL) crlTemp);
				i++;
			}
			
		}
		return crls;
	}

	/**
	 * Retorna uma lista de atributos não assinados de carimbo de tempo
	 * @return Lista de atributos não assinados de carimbo de tempo
	 */
	public List<String> getUnsignedAttributesForTimeStamp() {
		AttributeFactory attributeFactory = new AttributeFactory(this);

		List<String> timeStamps = new ArrayList<>();
		timeStamps.add(AttributeFactory.id_aa_ets_archiveTimeStampV2);
		timeStamps.add(AttributeFactory.id_aa_ets_escTimeStamp);
		timeStamps.add(AttributeFactory.id_aa_signatureTimeStamp);

		List<String> atts = new ArrayList<>();

		for (String optionalAttribute : getSelectedAttributes()) {

			if (!attributeFactory.isSigned(optionalAttribute)
					&& !timeStamps.contains(optionalAttribute)) {
				atts.add(optionalAttribute);
			}
		}

		return atts;
	}

	/**
	 * Configura um objeto {@link CadesAttributeIncluder} para ser utilizado em carimbos de tempo
	 * @param signerCertificate O certificado do assinante do carimbo
	 * @return O objeto {@link CadesAttributeIncluder} criado
	 */
	private CadesAttributeIncluder timestampAttributeIncluder(X509Certificate signerCertificate) {
		CadesAttributeIncluder cadesAttributeIncluder = new CadesAttributeIncluder();
		cadesAttributeIncluder.cadesSignature = this.cadesSignature;
		cadesAttributeIncluder.selectedAttributes = this.selectedAttributes;
		cadesAttributeIncluder.signerCertificate = signerCertificate;
		cadesAttributeIncluder.mimeType = this.mimeType;
		cadesAttributeIncluder.trustAnchors = this.cadesSignature.signaturePolicyInterface.getTimeStampTrustAnchors();
		return cadesAttributeIncluder;
	}

	/**
	 * Retorna o certificado do assinante presente na assinatura CMS
	 * @param cmsSignedData A assinatura
	 * @return O certificado do assinante da assinatura dada
	 */
	private X509Certificate retrieveSigningCertificate(CMSSignedData cmsSignedData) {
		SignerInformation signerInformation = cmsSignedData.getSignerInfos().iterator().next();
		Selector selector = signerInformation.getSID();
		Store store = cmsSignedData.getCertificates();
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

			X509Certificate timestampSigningCertificate = retrieveSigningCertificate(cmsSignedData);
			CadesAttributeIncluder timestampAttributeIncluder = timestampAttributeIncluder(timestampSigningCertificate);
			AttributeFactory attributeFactory = new AttributeFactory(timestampAttributeIncluder);

			for (String attributeName : attributesList) {
				SignatureAttribute signatureAttribute = attributeFactory
						.getAttribute(attributeName);
				signature.addUnsignedAttribute(signatureAttribute);
			}
			contentInfo = container.getSignedData().toASN1Structure();
			resultingContentInfo = contentInfo.getEncoded();
		} catch (IOException | CertificateEncodingException
				| NoSuchAlgorithmException | PbadException | TSPException | CMSException e) {
			Application.logger.log(Level.SEVERE, e.getMessage(), e);
		}

		return resultingContentInfo;
	}

	/**
	 * Cria a String de descrição do conteúdo baseado no seu MIME type
	 * @return A string de descrição criada
	 */
	public String getContentHintDescription() {

		String contentDescription = "";

		if (this.getContent() != null) {
			if (this.getContentMimeType() != null) {
				contentDescription = "Content-Type: "
						+ this.getContentMimeType();
			} else {
				// FIXME(mauricio): Boom!
			}

		} else {
			contentDescription = "Content-Type: application/pkcs7-signature";
		}

		return contentDescription;
	}

	/**
	 * Retorna o MIME type do conteúdo a ser assinado
	 * @return O MIME type do conteúdo
	 */
	private String getContentMimeType() {
		return this.mimeType;
	}

	/**
	 * Retorna a assinatura
	 * @return A assinatura
	 */
	public Signature getSignature() {
		return this.signature;
	}

	/**
	 * Atribue a assinatura CAdES
	 * @param signature A assinatura
	 */
	public void setSignature(Signature signature) {
		this.signature = signature;
	}

	/**
	 * Atribue o contêiner de assinatura CAdES
	 * @param signatureContainer O contêiner
	 */
	public void setSignatureContainer(SignatureContainer signatureContainer) {
		this.signatureContainer = (CadesSignatureContainer) signatureContainer;
	}

	/**
	 * Atribue o conteúdo a ser assinado
	 * @param contentToBeSigned2 O conteúdo a ser assinado
	 */
	public void setContentToBeSigned(CadesContentToBeSigned contentToBeSigned2) {
		this.contentToBeSigned = contentToBeSigned2;
	}

	/**
	 * Retorna o conteúdo a ser assinado
	 * @return O conteúdo a ser assinado
	 */
	public CadesContentToBeSigned getContentToBeSigned() {
		return this.contentToBeSigned;
	}

	public void setTrustAnchors(Set<TrustAnchor> trustAnchors) {
		this.trustAnchors = trustAnchors;
	}
}