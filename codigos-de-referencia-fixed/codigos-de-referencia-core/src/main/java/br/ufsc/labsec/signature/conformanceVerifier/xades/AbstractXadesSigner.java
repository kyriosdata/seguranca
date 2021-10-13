package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.cert.CertPath;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.ArrayList;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.logging.Level;

import javax.security.auth.x500.X500Principal;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.ContentToBeSigned;
import br.ufsc.labsec.signature.RevocationInformation;
import br.ufsc.labsec.signature.RevocationInformation.CRLResult;
import br.ufsc.labsec.signature.SignaturePolicyInterface.AdESType;
import br.ufsc.labsec.signature.SystemTime;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.ValidationDataService;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.DataObjectFormat;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SignaturePolicyIdentifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SignatureProductionPlace;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SigningTime;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.ArchiveTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CertificateValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CompleteCertificateRefs;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CompleteRevocationRefs;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.RevocationValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.SigAndRefsTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.SignatureTimeStamp;
import br.ufsc.labsec.signature.exceptions.AIAException;
import br.ufsc.labsec.signature.exceptions.EncodingException;

/**
 * Esta classe trata as partes em comum entre assinaturas XAdES e
 * carimbos do tempo.
 */
public abstract class AbstractXadesSigner {

	/**
	 * Arquivo a ser assinado
	 */
	protected File contentFile;
	/**
	 * Parte do arquivo a ser assinada
	 */
	protected ContentToBeSigned contentToBeSigned;
	/**
	 * Tipo da assinatura
	 */
	protected SignatureModeXAdES mode;
	/**
	 * Indica se o arquivo a ser assinado é XML
	 */
	protected boolean isXml;
	/**
	 * Fábrica de atributos
	 */
	protected AttributeFactory attributeFactory;
	/**
	 * Lista de atributos selecionados
	 */
	protected List<String> selectedAttributes;
	/**
	 * Lista de atributos obrigatórios assinados
	 */
	protected List<String> mandatedSignedAttributeList;
	/**
	 * Lista de atributos obrigatórios não-assinados
	 */
	protected List<String> mandatedUnsignedAttributeList;
	/**
	 * Componente de assinatura XAdES
	 */
	protected XadesSignatureComponent xadesSignatureComponent;
	/**
	 * Contêiner de assinatura XAdES
	 */
	protected SignatureContainer signatureContainer;
	/**
	 * Representa uma assinatura
	 */
	protected Signature signature;

	/**
	 * Construtor
	 * @param component Componente de assinatura XAdES
	 */
	public AbstractXadesSigner(XadesSignatureComponent component) {
		
		this.xadesSignatureComponent = component;
		
		this.selectedAttributes = new ArrayList<>();
		this.attributeFactory = new AttributeFactory(this);
	}

	/**
	 * Adiciona um atributo à assinatura
	 * @param attribute O atributo a ser selecionado
	 */
	public void selectAttribute(String attribute) {

		this.selectedAttributes.add(attribute.trim());

	}

	/**
	 * Remove um atributo da assinatura
	 * @param attribute O atributo a ser removido
	 */
	public void unselectAttribute(String attribute) {

		this.selectedAttributes.remove(attribute);

	}

	/**
	 * Retorna a lista de atributos assinados obrigatórios da assinatura
	 * @return A lista de atributos assinados obrigatórios da assinatura
	 */
	public List<String> getMandatedSignedAttributeList() {
		return this.mandatedSignedAttributeList;
	}

	/**
	 * Retorna a lista de atributos não assinados obrigatórios da assinatura
	 * @return A lista de atributos não assinados obrigatórios da assinatura
	 */
	public List<String> getMandatedUnsignedAttributeList() {
		return this.mandatedUnsignedAttributeList;
	}

	/**
	 * Retorna a lista de atributos assinados da assinatura
	 * @return A lista de atributos assinados da assinatura
	 */
	public List<String> getSignedAttributesAvailable() {

		List<String> signedAttributesAvaiable = new ArrayList<>();

		signedAttributesAvaiable.add(SignaturePolicyIdentifier.IDENTIFIER);
		signedAttributesAvaiable.add(DataObjectFormat.IDENTIFIER);
		signedAttributesAvaiable.add(SigningTime.IDENTIFIER);
		signedAttributesAvaiable.add(SignatureProductionPlace.IDENTIFIER);

		return signedAttributesAvaiable;

	}

	/**
	 * Retorna a lista de atributos não assinados disponíveis para a assinatura
	 * @return A lista de atributos não assinados da assinatura
	 */
	public List<String> getUnsignedAttributesAvailable() {

		List<String> unsignedAttributesAvaiable = new ArrayList<>();

		unsignedAttributesAvaiable.add(CompleteCertificateRefs.IDENTIFIER);
		unsignedAttributesAvaiable.add(CompleteRevocationRefs.IDENTIFIER);
		unsignedAttributesAvaiable.add(CertificateValues.IDENTIFIER);
		unsignedAttributesAvaiable.add(RevocationValues.IDENTIFIER);
		// unsignedAttributesAvaiable.add(AttributeCertificateRefs.IDENTIFIER);
		unsignedAttributesAvaiable.add(SignatureTimeStamp.IDENTIFIER);
		unsignedAttributesAvaiable.add(SigAndRefsTimeStamp.IDENTIFIER);
		unsignedAttributesAvaiable.add(ArchiveTimeStamp.IDENTIFIER);

		return unsignedAttributesAvaiable;

	}

	/**
	 * Retorna a lista de políticas de assinatura disponiveis
	 * @return A lista de políticas de assinatura
	 */
	public List<String> getPoliciesAvailable() {
		return this.xadesSignatureComponent.signaturePolicyInterface.getPoliciesAvaiable(
				AdESType.XAdES);

	}

	/**
	 * Retorna o caminho de certificação do certificado dado
	 * @param cert O certificado usado para gerar o caminho de certificação
	 * @return O caminho de certificação do certificado dado
	 */
	public CertPath getCertPath(X509Certificate cert) {
		return xadesSignatureComponent.certificateValidation.generateCertPath(cert,
				this.xadesSignatureComponent.signaturePolicyInterface.getSigningTrustAnchors(), new Time(SystemTime.getSystemTime()));
	}

	/**
	 * Retorna todos os certificados do caminho de certificação mais o
	 * certificado da âncora de confiança correspondente a este caminho
	 * @param certPath lista com os certificados do caminho de certificação
	 * @return lista com todos os certificados do caminho de certificação e o
	 * certificado da âncora de confiança
	 */
	public List<X509Certificate> addTrustAnchor(List<X509Certificate> certPath) {
		X509Certificate lastIntermediateCA = certPath.get(certPath.size() - 1);
		X500Principal trustPointIssuer = lastIntermediateCA.getIssuerX500Principal();
		X509Certificate trustPoint = (X509Certificate) this.xadesSignatureComponent.signaturePolicyInterface
				.getTrustPoint(trustPointIssuer).getTrustPoint();
		List<X509Certificate> certificates = new ArrayList<X509Certificate>(certPath);
		certificates.add(trustPoint);
		return certificates;
	}

	/**
	 * Retorna o conteúdo a ser assinado
	 * @return O conteúdo a ser assinado
	 */
	public ContentToBeSigned getContentToBeSigned() {
		return this.contentToBeSigned;
	}

	/**
	 * Retora o componente de assinatura XAdES
	 * @return O componente de assinatura XAdES
	 */
	public XadesSignatureComponent getComponent() {
		return this.xadesSignatureComponent;
	}

	/**
	 * Retorna os certificados do caminho de certificação e o
	 * certificado da âncora de confiança correspondente
	 * @return Lista com os certificados do caminho de certificação e o
	 * certificado da âncora de confiança
	 */
	public List<X509Certificate> getCertificateReferences() {
		X509Certificate signCert = attributeFactory.getSignerCertificate();
		List<X509Certificate> signCertPath = (List<X509Certificate>) this.getCertPath(signCert).getCertificates();
		signCertPath = this.addTrustAnchor(signCertPath);
		return signCertPath;
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
		List<String> addedCRLs = new ArrayList<>();

		for (X509Certificate x509Certificate : signCertPath) {
			List<RevocationInformation> revs = this.xadesSignatureComponent.revocationInformation;
			for (RevocationInformation revocationInformation : revs) {
				CRLResult result = revocationInformation.getCRLFromCertificate(x509Certificate);
				if (result != null) {
					X509CRL crl = (X509CRL) result.crl;
					String id = crl.getIssuerX500Principal().getName() + crl.getThisUpdate().toString();
					if (!addedCRLs.contains(id)) {
						crls.add(crl);
						addedCRLs.add(id);
					}
				}
			}
			
		}
		return crls;
	}

	/**
	 * Retorna o objeto que representa a assinatura
	 * @return A assinatura
	 */
	public Signature getSignature() {
		return this.signature;
	}

	/**
	 * Retorna a lista de atributos não-assinados
	 * @return Lista de atributos não-assinados
	 */
	public List<String> getUnsignedAttributes() {
		List<String> atts = new ArrayList<>();

		for (String optionalAttribute : this.selectedAttributes) {

			if (!this.attributeFactory.isSigned(optionalAttribute)) {
				atts.add(optionalAttribute);
			}
		}

		return atts;
	}

	/**
	 * Realiza a assinatura
	 * @param unsignedAttributes Lista de atributos não-assinados
	 * @param signatureContainerGenerator Gerador de contêineres de assinaturas XAdES
	 * @param signer dados do assinante
	 * @return Indica se o processo de assinatura foi concluído com sucesso
	 */
	protected boolean doSign(List<String> unsignedAttributes, SignatureContainerGenerator signatureContainerGenerator,
			SignerData signer) {
		/* Conteúdo a ser assinado */
		signatureContainerGenerator.addContentToBeSigned(contentToBeSigned);


		X509Certificate signerCertificate = this.xadesSignatureComponent.privateInformation.getCertificate();
		this.attributeFactory.setSignerCertificate(signerCertificate);
		
		try {
			 List<X509Certificate> certificates = ValidationDataService.downloadCertChainFromAia(signerCertificate);
			 this.getComponent().getSignatureIdentityInformation().addCertificates(certificates);
		} catch (AIAException e1) {}
		
		for (String mandatedAttribute : this.mandatedSignedAttributeList) {
			if (!this.selectedAttributes.contains(mandatedAttribute)) {
				this.selectedAttributes.add(mandatedAttribute);
			}
		}

		for (String mandatedAttribute : this.mandatedUnsignedAttributeList) {
			if (!this.selectedAttributes.contains(mandatedAttribute)) {
				this.selectedAttributes.add(mandatedAttribute);
			}
		}

		try {
			// for (String mandetedSignedAttribute :
			// this.mandatedSignedAttributeList) {
			// SignatureAttribute attribute =
			// attributeFactory.getAttribute(mandetedSignedAttribute);
			// if (attribute == null)
			// return false;
			// signatureContainerGenerator.addAttribute(attribute);
			// }

			for (String attributeIdentifier : selectedAttributes) {

				if (attributeFactory.isSigned(attributeIdentifier)) {
					SignatureAttribute attribute = attributeFactory.getAttribute(attributeIdentifier);
					if (attribute == null) {
						clearFields();
						return false;
					}
						
					signatureContainerGenerator.addAttribute(attribute);
				} else
					unsignedAttributes.add(attributeIdentifier);
			}

			/* Atributos Comuns */
			// SignatureAttribute signingCertificate =
			// attributeFactory.getAttribute(SigningCertificate.IDENTIFIER);
			// if (signingCertificate == null)
			// return false;
			// signatureContainerGenerator.addAttribute(signingCertificate);

			signatureContainerGenerator.setSigner(signer);

			/* Assinatura */
			this.signature = this.sign(signatureContainerGenerator);
			if (signature == null) {
				clearFields();
				return false;
			}

			// for (String mandetedUnSignedAttribute :
			// this.mandatedUnsignedAttributeList) {
			// if
			// (!signature.getSignatureAt(0).getAttributeList().contains(mandetedUnSignedAttribute))
			// {
			// SignatureAttribute attribute =
			// attributeFactory.getAttribute(mandetedUnSignedAttribute);
			// if (attribute == null)
			// return false;
			// signature.getSignatureAt(0).addUnsignedAttribute(attribute);
			// }
			// }

			for (String unsignedOptionalAttribute : unsignedAttributes) {

				if (!signature.getAttributeList().contains(unsignedOptionalAttribute)
						&& !unsignedOptionalAttribute.equals(ArchiveTimeStamp.IDENTIFIER)
						&& !unsignedOptionalAttribute.equals(SigAndRefsTimeStamp.IDENTIFIER)) {
					SignatureAttribute attribute = attributeFactory.getAttribute(unsignedOptionalAttribute);
					if (attribute == null) {
						clearFields();
						return false;
					}
					signature.addUnsignedAttribute(attribute);
				}
			}

			if (unsignedAttributes.contains(SigAndRefsTimeStamp.IDENTIFIER)) {
				SignatureAttribute attribute = attributeFactory.getAttribute(SigAndRefsTimeStamp.IDENTIFIER);
				if (attribute == null) {
					clearFields();
					return false;
					}
				signature.addUnsignedAttribute(attribute);
			}

			if (unsignedAttributes.contains(ArchiveTimeStamp.IDENTIFIER)) {
				SignatureAttribute attribute = attributeFactory.getAttribute(ArchiveTimeStamp.IDENTIFIER);
				if (attribute == null) {
					clearFields();
					return false;
				}
				signature.addUnsignedAttribute(attribute);
			}

			clearFields();
			
		} catch (Exception e) {
			Application.logger.log(Level.SEVERE, e.getMessage(), e);
			clearFields();
			return false;
		}

		return true;
	}

	/**
	 * Salva a assinatura gerada em formato .xml
	 * @return Indica se a assinatura foi salva com sucesso
	 */
	public boolean saveSignature() throws EncodingException {
		OutputStream outputStream = xadesSignatureComponent.ioService.save("xml");

		
		if (outputStream != null && signatureContainer != null) {
			signatureContainer.encode(outputStream);
		} else {
			return false;
		}
		return true;
		
	}

	/**
	 * Limpa a lista de atributos selecionados
	 */
	private void clearFields() {
		this.selectedAttributes = new ArrayList<>();
	}

	/**
	 * Retorna a fábrica de atributos
	 * @return A fábrica de atributos
	 */
	public AttributeFactory getAttributeFactory() {
		return attributeFactory;
	}

	/**
	 * Realiza a assinatura
	 * @param signatureContainerGenerator Gerador de contêineres de assinaturas XAdES
	 * @return Indica se o processo de assinatura foi concluído com sucesso
	 */
	protected abstract Signature sign(SignatureContainerGenerator signatureContainerGenerator);

}