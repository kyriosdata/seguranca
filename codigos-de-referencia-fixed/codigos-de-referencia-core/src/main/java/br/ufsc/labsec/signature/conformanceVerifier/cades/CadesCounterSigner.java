package br.ufsc.labsec.signature.conformanceVerifier.cades;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import br.ufsc.labsec.signature.SignatureDataWrapper;
import br.ufsc.labsec.signature.SignaturePolicyInterface.AdESType;
import br.ufsc.labsec.signature.signer.SignerType;
import org.bouncycastle.asn1.cms.Attribute;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.CertificateCollection;
import br.ufsc.labsec.signature.CounterSigner;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SigningCertificateInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaEtsSigPolicyId;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificate;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificateV2;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsCertValues;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsRevocationValues;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.CadesSignatureException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.CertValuesException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

/**
 * Esta classe adiciona uma contra-assinatura CAdES a um documento.
 * Estende {@link AbstractCadesSigner} e implementa {@link CounterSigner}.
 */
public class CadesCounterSigner extends AbstractCadesSigner implements
		CounterSigner {

	private static final String ATTRIBUTE_NOT_FOUND = "Atributo não encontrado na assinatura";
	private static final String SIGNINGCERTIFICATEV1_ATTRIBUTE_DECODING_ERROR = "Não foi possível decodificar corretamente o atributo SigningCertificate";
	private static final String SIGNINGCERTIFICATEV2_ATTRIBUTE_DECODING_ERROR = "Não foi possível decodificar o atributo SigningCertificateV2";
	private static final String GET_ATTRIBUTE_FAILED = "Obtenção de atributo falhou";

	/**
	 * Assinatura CAdES
	 */
	private CadesSignature selectedSignature;

	/**
	 * Construtor
	 * @param cadesSignature Componente de assinatura CAdES
	 */
	public CadesCounterSigner(CadesSignatureComponent cadesSignature) {
		super(cadesSignature);
	}

	/**
	 * Inicializa o gerador de contêiner de assinatura
	 * @param target O endereço do arquivo de assinatura
	 * @param signedContent O endereço do conteúdo assinado
	 * @param signaturePolicy O OID da política usada
	 */
	public void selectTarget(String target, String signedContent,
			String signaturePolicy) {
		byte[] signatureBytes = getFileBytes(target);
		byte[] signedContentBytes = null;
		try {
			this.attributeIncluder
					.setSignatureContainer(new CadesSignatureContainer(
							signatureBytes));
			if (this.attributeIncluder.getSignatureContainer()
					.hasDetachedContent()) {
				if (signedContent != null && !signedContent.isEmpty()) {
					signedContentBytes = getFileBytes(signedContent);
					this.attributeIncluder.getSignatureContainer()
							.setSignedContent(signedContentBytes);
				}
			}
		} catch (CadesSignatureException e1) {
			Application.logger.log(Level.SEVERE, e1.getMessage(), e1);
		} catch (EncodingException e1) {
			Application.logger.log(Level.SEVERE, e1.getMessage(), e1);
		} catch (PbadException e) {
			this.attributeIncluder.getCadesSignature().getApplication().logger
					.log(Level.SEVERE, "Erro ao ler o conteudo assinado", e);
		}

		this.attributeIncluder.getCadesSignature().signaturePolicyInterface
				.setActualPolicy(signaturePolicy, null, AdESType.CAdES);
		this.attributeIncluder.setSelectedAttributes(new ArrayList<String>());
		this.attributeIncluder.getSelectedAttributes().addAll(
				this.getMandatedSignedAttributeList());
		this.attributeIncluder.getSelectedAttributes().addAll(
				this.getMandatedUnsignedAttributeList());

		this.attributeIncluder.getSelectedAttributes().remove(
				AttributeFactory.id_contentType);
	}

	/**
	 * Carrega as informações da assinatura indicada no contâiner CAdES
	 * @param signatureSelected O identificador da assinatura
	 */
	public void selectSignature(String signatureSelected) {
		int i = this.getAvailableSignatures().indexOf(signatureSelected);
		try {
			this.selectedSignature = this.attributeIncluder
					.getSignatureContainer().getSignatureAt(i);
			addValidationData(this.selectedSignature);
		} catch (EncodingException e1) {
			Application.logger.log(Level.SEVERE, e1.getMessage(), e1);
		}  catch (CertificateException e) {
			this.attributeIncluder.getCadesSignature().getApplication().logger
					.log(Level.SEVERE,
							"Erro não foi possível extrair os certificados do campo certificates",
							e);
		} catch (IOException e) {
			this.attributeIncluder.getCadesSignature().getApplication().logger
					.log(Level.SEVERE,
							"Erro de entrada/saida nos certificados do campo certificates",
							e);
		}
	}

	/**
	 * Retorna uma lista de subject names dos certificados na assinatura
	 * @return A lista de assinaturas no documento
	 */
	@Override
	public List<String> getAvailableSignatures() {
		if (this.attributeIncluder.getSignatureContainer() != null) {
			List<CadesSignature> signatures = null;
			try {
				signatures = this.attributeIncluder.getSignatureContainer()
						.getSignatures();
			} catch (EncodingException e) {
				Application.logger.log(Level.SEVERE, e.getMessage(), e);
			}
			List<String> names = new ArrayList<String>();
			SigningCertificateInterface idAaSigningCertificate = null;

			idAaSigningCertificate = addCertificatesAndAddNameFromSigningCertificate(
					signatures, names, idAaSigningCertificate);

			return names;
		}

		return null;
	}

	/**
	 * Adiciona um atributo à assinatura
	 * @param attribute O atributo a ser selecionado
	 */
	public void selectAttribute(String attribute) {
		if (!this.attributeIncluder.getSelectedAttributes().contains(attribute)) {
			this.attributeIncluder.getSelectedAttributes().add(attribute);
		}

	}

	/**
	 * Remove um atributo da assinatura
	 * @param attribute O atributo a ser removido
	 */
	public void unselectAttribute(String attribute) {
		if (this.attributeIncluder.getSelectedAttributes().contains(attribute)) {
			this.attributeIncluder.getSelectedAttributes().remove(attribute);
		}
	}

	/**
	 * Retorna a lista de atributos assinados disponíveis da assinatura
	 * @return A lista de atributos assinados disponíveis da assinatura
	 */
	public List<String> getSignedAttributesAvailable() {
		List<String> attributesAvailable = new ArrayList<String>();

		attributesAvailable.add(AttributeFactory.id_aa_ets_signerLocation);
		attributesAvailable.add(AttributeFactory.id_aa_contentHint);
		attributesAvailable.add(AttributeFactory.id_signingTime);
		attributesAvailable.add(AttributeFactory.id_messageDigest);
		attributesAvailable.add(AttributeFactory.id_aa_signingCertificate);

		return attributesAvailable;
	}

	/**
	 * Retorna a lista de atributos não assinados disponíveis da assinatura
	 * @return A lista de atributos não assinados disponíveis da assinatura
	 */
	public List<String> getUnsignedAttributesAvailable() {
		List<String> attributesAvailable = new ArrayList<String>();

		attributesAvailable.add(AttributeFactory.id_aa_ets_CertificateRefs);
		attributesAvailable.add(AttributeFactory.id_aa_ets_revocationRefs);
		attributesAvailable.add(AttributeFactory.id_aa_ets_escTimeStamp);
		attributesAvailable.add(AttributeFactory.id_aa_ets_certValues);
		attributesAvailable.add(AttributeFactory.id_aa_ets_revocationValues);
		attributesAvailable.add(AttributeFactory.id_aa_ets_archiveTimeStampV2);
		attributesAvailable.add(AttributeFactory.id_aa_signatureTimeStamp);

		return attributesAvailable;
	}

	/**
	 * Busca pelo certificado do assinante e o adiciona na lista de issuer+serial dada
	 * @param names Lista de issuer+serial do certificado do signatário presente
	 *            no atributo
	 * @param idAaSigningCertificate Atributo presente na assinatura
	 * @param signatures Lista de assinaturas CAdES
	 * @return O atributo SigningCertificate da assinatura
	 */
	private SigningCertificateInterface addCertificatesAndAddNameFromSigningCertificate(
			List<CadesSignature> signatures, List<String> names,
			SigningCertificateInterface idAaSigningCertificate) {
		for (CadesSignature signature : signatures) {

			idAaSigningCertificate = addNameFromSigningCertificate(names,
					idAaSigningCertificate, signature);

		}
		return idAaSigningCertificate;
	}

	/**
	 * Adiciona novos certificados e CRLs ao SignatureIdentityInformation da assinatura
	 * de acordo com a presença dos atributos CertificateValues e RevocationValues
	 * @param signature A assinatura CAdES
	 * @throws CertificateException Ocorre esta exceção quando for encontrado algum erro no
	 *             certificado
	 * @throws IOException Ocorre esta exceção quando for encontrado algum erro no
	 *             arquivo de entrada/saída
	 */
	private void addValidationData(CadesSignature signature)
			throws CertificateException, IOException {
		List<X509Certificate> certValuesCertificates;
		List<X509CRL> crlsList;

		this.attributeIncluder.getCadesSignature().getSignatureIdentityInformation().addCertificates(signature.getCertificates());
		if (signature.getAttributeList().contains(IdAaEtsCertValues.IDENTIFIER)) {
			certValuesCertificates = this
					.getSignatureCertificateValues(signature);
			this.attributeIncluder.getCadesSignature().getSignatureIdentityInformation().addCertificates(certValuesCertificates);
			if (signature.getAttributeList().contains(
					IdAaEtsRevocationValues.IDENTIFIER)) {
				crlsList = this.getSignatureRevocationValues(signature);
				this.attributeIncluder.getCadesSignature().getSignatureIdentityInformation().addCrl(certValuesCertificates, crlsList);
			}
		}
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
					SIGNINGCERTIFICATEV2_ATTRIBUTE_DECODING_ERROR, e);
		}

		boolean nameFound = true;
		if (idAaSigningCertificate != null) {
			try {
				
				int i = 0;
				X509Certificate certificate = null;
				List<CertificateCollection> certList = attributeIncluder.getCadesSignature().certificateCollection;
				
				while(certificate == null && i < certList.size()) {
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
	 * @param nameFound Indica se o issuer+serial foi encontrado
	 * @return Indica se o issuerSerial foi encontrado
	 */
	private boolean addIssuerSerial(List<String> names,
			SigningCertificateInterface idAaSigningCertificate,
			boolean nameFound) {
		try {
			
			int i = 0;
			X509Certificate certificate = null;
			List<CertificateCollection> certList = attributeIncluder.getCadesSignature().certificateCollection;
			
			while(certificate == null && i < certList.size()) {
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
	 * Realiza a contra-assinatura
	 * @return Indica se a contra-assinatura foi realizada com sucesso
	 */
	@Override
	public boolean counterSign() {
		boolean error = false;
		List<String> unsignedAttributesList = new ArrayList<>();

		String policyId = this.attributeIncluder.getCadesSignature().signaturePolicyInterface
				.getPolicyId();
		byte[] policyHash = this.attributeIncluder.getCadesSignature().signaturePolicyInterface
				.getSignPolicyHash();
		String policyHashAlgorithm = this.attributeIncluder.getCadesSignature().signaturePolicyInterface
				.getHashAlgorithmId();

		String policyURL = this.attributeIncluder.getCadesSignature().signaturePolicyInterface
				.getURL(AdESType.CAdES);

		IdAaEtsSigPolicyId sigPolicyId = new IdAaEtsSigPolicyId(policyId,
				policyHashAlgorithm, policyHash, policyURL);

		this.signatureContainerGenerator = new CounterSignatureGenerator(
				sigPolicyId, attributeIncluder.getCadesSignature());

		CadesSignatureToBeSigned contentToBeSigned = new CadesSignatureToBeSigned(
				this.selectedSignature);
		this.signatureContainerGenerator
				.addContentToBeSigned(contentToBeSigned);
		this.attributeIncluder.setContentToBeSigned(contentToBeSigned);

		return doSign(error, unsignedAttributesList,
				this.signatureContainerGenerator);
	}

	/**
	 * Realiza a contra-assinatura
	 * @return {@link Signature} que contém a assinatura gerada
	 */
	@Override
	protected Signature sign(SignatureContainerGenerator signatureContainerGenerator) throws CadesSignatureException {
		CounterSignatureGenerator counterSignatureGenerator = (CounterSignatureGenerator) signatureContainerGenerator;
		return counterSignatureGenerator.counterSign();
	}

	/**
	 * Verifica se o arquivo é um arquivo assinado XAdES
	 * @param filePath O endereço do arquivo a ser verificado
	 * @return Indica se o arquivo é um arquivo assinado XAdES
	 */
	@Override
	public boolean isSignature(String filePath) {
		byte[] signatureBytes = getFileBytes(filePath);
		try {
			new CadesSignatureContainer(signatureBytes);
		} catch (CadesSignatureException | EncodingException e) {
			Application.logger.log(Level.FINE, e.getMessage(), e);
			return false;
		}

		return true;
	}

	/**
	 * Retorna a necessidade de conteúdo assinado
	 * @return Indice se é necessário conteúdo assinado
	 */
	@Override
	public boolean needSignedContent() {
		try {
			return this.signatureContainer.hasDetachedContent();
		} catch (EncodingException e) {
			Application.logger.log(Level.SEVERE, e.getMessage(), e);
		}

		return false;
	}

	@Override
	public SignatureDataWrapper getSignature(String filename, InputStream target, SignerType policyOid) {
		// TODO
		return null;
	}
}
