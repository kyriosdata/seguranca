package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.io.File;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import br.ufsc.labsec.signature.SignaturePolicyInterface.AdESType;
import org.w3c.dom.Element;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.CounterSigner;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.DataObjectFormat;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SignaturePolicyIdentifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SigningCertificate;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CertificateValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.RevocationValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.RevocationValuesException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.XadesSignatureContainerException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe adiciona uma contra-assinatura XAdES a um documento.
 * Estende {@link AbstractXadesSigner} e implementa {@link CounterSigner}.
 */
public class XadesCounterSigner extends AbstractXadesSigner implements CounterSigner {

	/**
	 * Assinatura XAdES
	 */
	private XadesSignature selectedSignature;

	/**
	 * Construtor
	 * @param xadesSignatureComponent Componente de assinatura XAdES
	 */
	public XadesCounterSigner(XadesSignatureComponent xadesSignatureComponent) {
		
		super(xadesSignatureComponent);
		
		this.xadesSignatureComponent = xadesSignatureComponent;

		this.selectedAttributes = new ArrayList<>();

		this.attributeFactory = new AttributeFactory(this);
	}

	/**
	 * Inicializa o gerador de contêiner de assinatura
	 * @param target O endereço do arquivo de assinatura
	 * @param signedContent O endereço do conteúdo assinado
	 * @param signaturePolicy O OID da política usada
	 */
	@Override
	public void selectTarget(String target, String signedContent, String signaturePolicy) {
		this.contentFile = new File(target);
		this.xadesSignatureComponent.signaturePolicyInterface.setActualPolicy(signaturePolicy, null,
				AdESType.XAdES);
		this.mandatedSignedAttributeList = this.xadesSignatureComponent.signaturePolicyInterface
				.getMandatedSignedAttributeList();
		this.mandatedUnsignedAttributeList = this.xadesSignatureComponent.signaturePolicyInterface
				.getMandatedUnsignedSignerAttributeList();
		try {
			this.signatureContainer = new XadesSignatureContainer(new File(target));
		} catch (XadesSignatureContainerException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * Carrega as informações da assinatura indicada no contâiner XAdES
	 * @param target O identificador da assinatura
	 */
	@Override
	public void selectSignature(String target) {
		int i = this.getAvailableSignatures().indexOf(target);
		try {
			this.selectedSignature = this.signatureContainer.getSignatureAt(i);
			addValidationData(this.signatureContainer.getSignatureAt(i));
		} catch (EncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * Realiza a contra-assinatura
	 * @return Indica se a contra-assinatura foi realizada com sucesso
	 */
	@Override
	public boolean counterSign() {

		// Removendo os obrigatórios que não podem ser incluídos na
		// contra-assinatura
		this.selectedAttributes.remove(SignaturePolicyIdentifier.IDENTIFIER);
		this.selectedAttributes.remove(DataObjectFormat.IDENTIFIER);
		this.mandatedSignedAttributeList.remove(DataObjectFormat.IDENTIFIER);

		List<String> unsignedOptionalAttributes = new ArrayList<>();

		PrivateKey privateKey = this.xadesSignatureComponent.privateInformation.getPrivateKey();

		X509Certificate signerCertificate = this.xadesSignatureComponent.privateInformation.getCertificate();

		SignatureContainerGenerator signatureContainerGenerator = null;
		SignerData signer = null;
		try {
			signer = new SignerData(signerCertificate, privateKey);

			this.contentToBeSigned = new XadesSignatureToBeSigned(this.selectedSignature);

			SignaturePolicyIdentifier sigPolicyIdentifier = (SignaturePolicyIdentifier) attributeFactory
					.getAttribute(SignaturePolicyIdentifier.IDENTIFIER);
			signatureContainerGenerator = new CounterSignatureGenerator(sigPolicyIdentifier, xadesSignatureComponent);
		} catch (Exception e) {
			Application.logger.log(Level.SEVERE, e.getMessage(), e);
			return false;
		}

		return this.doSign(unsignedOptionalAttributes, signatureContainerGenerator, signer);
	}

	/**
	 * Retorna uma lista de issuerName+serialNumber dos certificados na assinatura
	 * @return A lista de assinaturas no documento
	 */
	@Override
	public List<String> getAvailableSignatures() {
		if (this.signatureContainer != null) {
			int signatureCount = this.signatureContainer.getSignatureCount();

			List<String> result = new ArrayList<String>();

			for (int i = 0; i < signatureCount; i++) {
				this.extractSignatureName(result, i);
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
		XadesSignature xadesSignature;
		try {
			xadesSignature = this.signatureContainer.getSignatureAt(signatureIndex);

			if (xadesSignature.getAttributeList().contains(SigningCertificate.IDENTIFIER)) {
				SigningCertificate signingCertificate = null;

				signingCertificate = new SigningCertificate(xadesSignature.getEncodedAttribute(SigningCertificate.IDENTIFIER));

				result.add(signingCertificate.getIssuerName() + " " + signingCertificate.getSerialNumber());
			}

		} catch (EncodingException e1) {
			Application.logger.log(Level.SEVERE, "Erro não foi possível decodificar a assinatura.", e1);
		} catch (SignatureAttributeNotFoundException e) {
			Application.logger.log(Level.SEVERE, "Erro não foi possível encontrar a assinatura.", e);
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
		this.xadesSignatureComponent.getSignatureIdentityInformation().addCertificates(xadesSignature.getCertificatesAtKeyInfo());
		if (xadesSignature.getAttributeList().contains(CertificateValues.IDENTIFIER)) {
			certValuesCertificates = this.getCertificateValues(xadesSignature);
			this.xadesSignatureComponent.getSignatureIdentityInformation().addCertificates(certValuesCertificates);
			if (xadesSignature.getAttributeList().contains(RevocationValues.IDENTIFIER)) {
				crlsList = this.getSignatureRevocationValues(xadesSignature);
				this.xadesSignatureComponent.getSignatureIdentityInformation().addCrl(certValuesCertificates, crlsList);
			}
		}
	}

	/**
	 * Retorna a lista de CRLs do atributo RevocationValues
	 * @param xadesSignature A assinatura XAdES
	 * @return A lista de CRLs dos certificados presentes na assinatura
	 */
	private List<X509CRL> getSignatureRevocationValues(XadesSignature xadesSignature) {
		RevocationValues revValues = null;
		try {
			Element element = xadesSignature.getEncodedAttribute(RevocationValues.IDENTIFIER);
			revValues = new RevocationValues(element);
			return revValues.getCrlValues();
		} catch (SignatureAttributeNotFoundException e) {
			Application.logger.log(Level.SEVERE, "Atributo não encontrado na assinatura", e);
		} catch (RevocationValuesException e) {
			Application.logger.log(Level.SEVERE, "Erro no atributo RevocationValues", e);
		} catch (SignatureAttributeException e) {
			Application.logger.log(Level.SEVERE, "Erro no atributo RevocationValues da assinatura", e);
		}

		return null;
	}

	/**
	 * Retorna a lista de certificados do atributo CertificateValues
	 * @param xadesSignature A assinatura XAdES
	 * @return A lista de certificados presente no atributo da assinatura
	 *         CertificateValues
	 */
	private List<X509Certificate> getCertificateValues(XadesSignature xadesSignature) {
		CertificateValues certValues = null;
		try {
			Element element = xadesSignature.getEncodedAttribute(CertificateValues.IDENTIFIER);
			certValues = new CertificateValues(element);
			return certValues.getCertValues();
		} catch (SignatureAttributeNotFoundException e) {
			Application.logger.log(Level.SEVERE, "Atributo não encontrado na assinatura", e);
		} catch (EncodingException e) {
			Application.logger.log(Level.SEVERE, "Erro ao codificar o atributo CertValues", e);
		} catch (br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.CertValuesException e) {
			Application.logger.log(Level.SEVERE, "Erro no atributo CertValues", e);
		}

		return null;
	}

	/**
	 * Verifica se o arquivo é um arquivo assinado XAdES
	 * @param filePath O endereço do arquivo a ser verificado
	 * @return Indica se o arquivo é um arquivo assinado XAdES
	 */
	@Override
	public boolean isSignature(String filePath) {
		try {
			XadesSignatureContainer sig = new XadesSignatureContainer(new File(filePath));
			return sig.getSignatureCount() > 0;
		} catch (XadesSignatureContainerException e) {
			Application.logger.log(Level.FINE, e.getMessage(), e);
			return false;
		}
	}

	/**
	 * Realiza a contra-assinatura
	 * @param signatureContainerGenerator Gerador de contêiner de assinatura XAdES
	 * @return Indica se a contra-assinatura foi realizada com sucesso
	 */
	@Override
	protected Signature sign(SignatureContainerGenerator signatureContainerGenerator) {
		CounterSignatureGenerator counterSignatureGenerator = (CounterSignatureGenerator) signatureContainerGenerator;

		try {
			counterSignatureGenerator.sign();
			return this.selectedSignature.getCounterSignature(this.xadesSignatureComponent.privateInformation
					.getCertificate());
		} catch (PbadException e) {
			Application.logger.log(Level.WARNING, e.getMessage(), e);
		}

		return null;
	}

	/**
	 * Retorna a necessidade de conteúdo assinado
	 * @return Indice se é necessário conteúdo assinado
	 */
	@Override
	public boolean needSignedContent() {
		return false;
	}

}
