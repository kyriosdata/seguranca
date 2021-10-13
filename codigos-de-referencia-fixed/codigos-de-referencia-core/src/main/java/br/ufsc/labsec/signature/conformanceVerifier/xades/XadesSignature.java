/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;

import javax.security.auth.x500.X500Principal;
import javax.xml.crypto.*;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.XMLSignature.SignatureValue;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cms.SignerId;
import org.w3c.dom.Attr;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.CounterSignatureInterface;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SigningCertificate;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.ArchiveTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CounterSignature;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.CounterSignatureException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureModeException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.TimeStampException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.UniqueAttributeException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.XadesSignatureContainerException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.XmlProcessingException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import br.ufsc.labsec.signature.exceptions.VerificationException;

/**
 * Esta classe representa uma assinatura do tipo XAdES.
 * Implementa {@link Signature}.
 */
public class XadesSignature implements Signature {

	private static final String SIGNED_SIGNATURE_PROPERTIES = "SignedSignatureProperties";
	private static final String COLON = ":";
	private static final String UNSIGNED_PROPERTIES = "UnsignedProperties";
	private static final String XADES_COUNTER_SIGNATURE = "XAdES:CounterSignature";
	private static final String SIGNING_CERTIFICATE = "SigningCertificate";
	private static final String SIGNED_PROPERTIES = "SignedProperties";
	private static final String DOM = "DOM";
	private static final String XADES_ARCHIVE_TIME_STAMP = "XAdES:ArchiveTimeStamp";
	private static final String REFERENCE = "Reference";
	private static final String SPURI = "SPURI";
	private static final String SIG_POLICY_QUALIFIERS = "SigPolicyQualifiers";
	private static final String SIGNED_INFO = "SignedInfo";
	private static final String ID = "Id";
	private static final String SIGNATURE_VALUE = "SignatureValue";
	private static final String QUALIFYING_PROPERTIES = "QualifyingProperties";
	private static final String SIGNATURE_TIME_STAMP = "SignatureTimeStamp";
	private static final String COMPLETE_CERTIFICATE_REFS = "CompleteCertificateRefs";
	private static final String COMPLETE_REVOCATION_REFS = "CompleteRevocationRefs";
	private static final String ATTRIBUTE_CERTIFICATE_REFS = "AttributeCertificateRefs";
	private static final String ATTRIBUTE_REVOCATION_REFS = "AttributeRevocationRefs";
	private static final String TYPE = "Type";
	private static final String DS_REFERENCE = "ds:Reference";
	private static final String SIGNATURE_POLICY_IDENTIFIER = "SignaturePolicyIdentifier";
	private static final String UNSIGNED_DATA_OBJECT_PROPERTIES = "UnsignedDataObjectProperties";
	private static final String UNSIGNED_SIGNATURE_PROPERTIES = "UnsignedSignatureProperties";
	private static final String SIGNED_DATA_OBJECT_PROPERTIES = "SignedDataObjectProperties";
	private static final String REVOCATION_VALUES = "RevocationValues";
	private static final String CERTIFICATE_VALUES = "CertificateValues";
	/**
	 * O documento de assinatura
	 */
	protected Document xml;
	/**
	 * O nodo XML da assinatura
	 */
	protected Element signatureElement;
	/**
	 * Algoritmo de canonização aplicado ao SignedInfo
	 */
	private String canonicalizationMethodAlgorithm;
	/**
	 * Contêiner de assinaturas XAdES
	 */
	private XadesSignatureContainer container;
	/**
	 * Lista de transformações de uma referência
	 */
	private List<Transform> transforms;
	/**
	 * Lista de todas as transformações na assinatura
	 */
	private List<Transform> allTransforms;

	/**
	 * Constrói uma assinatura XAdES a partir da representação DOM do documento
	 * XML assinado, e do elemento que representa a assinatura no documento.
	 * @param xml A representação DOM de um documento XML
	 * @param signature O elemento que representa a assinatura no documento
	 * @param xadesSignatureContainer O contêiner de assinatura XAdES
	 */
	protected XadesSignature(Document xml, Element signature,
			XadesSignatureContainer xadesSignatureContainer) {
		this.xml = xml;
		this.signatureElement = signature;
		Node canonicalizationMethod = this.signatureElement
				.getElementsByTagName("ds:CanonicalizationMethod").item(0);
		if (canonicalizationMethod == null) {
			canonicalizationMethod = this.signatureElement
					.getElementsByTagName("CanonicalizationMethod").item(0);
		}
		this.canonicalizationMethodAlgorithm = canonicalizationMethod
				.getAttributes().getNamedItem("Algorithm").getTextContent();
		this.container = xadesSignatureContainer;
		this.transforms = new ArrayList<>();
		this.allTransforms = new ArrayList<>();
	}

	/**
	 * Informa em qual {@link Element} especifico está a representação da
	 * assinatura
	 * @return O nodo que contém a assinatura na estrutura XML do documento assinado
	 */
	public Element getSignatureElement() {
		return this.signatureElement;
	}

	/**
	 * Verifica a assinatura XAdES baseado no
	 * documento(http://www.w3.org/TR/XAdES/) e anexa ao report.
	 * @param signerCertificate O certificado do signatário
	 * @param sigReport O relátorio da assinatura
	 * @return Indica se a assinatura XAdES está de acordo com os padrões do
	 *         documento (http://www.w3.org/TR/XAdES/)
	 * @throws VerificationException Exceção em caso de erro durante a verificação
	 */
	public boolean verify(X509Certificate signerCertificate, SignatureReport sigReport) throws VerificationException {
		boolean valid = true;
		
		NodeList elements = this.signatureElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "SignedProperties");
		if (elements.getLength() != 1) {
			throw new VerificationException("The signature should have one and only one XAdES:SignedProperties.");
		} else {
			Element signedProperties = (Element) elements.item(0);
			NamedNodeMap attributes = signedProperties.getAttributes();
			if (attributes.getLength() != 1) {
				throw new VerificationException("The XAdES:SignedProperties should have one and only one attribute called Id.");
			} else {
				Attr attribute = (Attr) attributes.item(0);
				signedProperties.setIdAttributeNode(attribute, true);	
			}
			
		}
		
		try {
			DOMValidateContext validateContext = null;
			validateContext = getDOMValidateContext(signerCertificate);
			XMLSignature xmlSignature = setDefaultNamespacePrefixAndUnmarchalSignature(validateContext);
			@SuppressWarnings("unchecked")
			List<Reference> references = xmlSignature.getSignedInfo().getReferences();
			
			boolean hasOneDetached = false;
			for (Reference reference: references) {
				if (!hasOneDetached & isDetached(reference.getURI())) {
					hasOneDetached = true;
				} else if (isDetached(reference.getURI())) {
					throw new VerificationException(VerificationException.MORE_THAN_ONE_DETACHED_CONTENT);
				}
			}
			Iterator<Reference> i = references.iterator();
			Reference reference = null;
			while (valid && i.hasNext()) {
				reference = i.next();
				boolean validReference = false;
				validReference = validateReferenceDetachedOrAttached(
						validateContext, reference);
				sigReport.addReferences(validReference);
				valid &= validReference;
			}
			if (references.isEmpty()) {
				sigReport.setMessageDigest(null);
			} else {
				sigReport.setMessageDigest(references.get(references.size()-1).getDigestValue());
			}
			valid = validateSignatureValue(valid, validateContext, xmlSignature);
		} catch (MarshalException | XMLSignatureException
				| NoSuchAlgorithmException | IOException | URISyntaxException marshalException) {
			throw new VerificationException(marshalException);
		}

		sigReport.setHash(valid);
		return valid;
	}

	/**
	 * Cria um objeto {@link DOMValidateContext}, que contém informações do contexto
	 * do arquivo para realizar a validação da assinatura
	 * @param signerCertificate O certificado do assinante
	 * @return O objeto {@link DOMValidateContext} gerado
	 */
	private DOMValidateContext getDOMValidateContext(
			X509Certificate signerCertificate) {
		DOMValidateContext validateContext;
		if (signerCertificate != null) {
			validateContext = new DOMValidateContext(
					signerCertificate.getPublicKey(), this.signatureElement);
		} else {
			validateContext = new DOMValidateContext(new KeySelector() {
				@Override
				public KeySelectorResult select(KeyInfo keyInfo,
						Purpose purpose, AlgorithmMethod method,
						XMLCryptoContext context) throws KeySelectorException {
					throw new KeySelectorException(
							"Não foi possível encontrar a chave do assinante.");
				}
			}, this.signatureElement);
		}
		return validateContext;
	}

	/**
	 * Atribue o valor padrão para o namespace do arquivo e cria
	 * um novo objeto {@link XMLSignature} com as informações do arquivo anterior
	 * mas com seu namespace atualizado
	 * @param validateContext O contexto de validação do documento
	 * @return Um objeto de assinatura com o novo namespace
	 * @throws MarshalException Exceção em caso de erro durante o processo de unmarshal
	 */
	private XMLSignature setDefaultNamespacePrefixAndUnmarchalSignature(
			DOMValidateContext validateContext) throws MarshalException {
		XMLSignatureFactory xmlSigFac = XMLSignatureFactory.getInstance(DOM);
		validateContext
				.setDefaultNamespacePrefix(NamespacePrefixMapperImp.XMLDSIG_NS);
		XMLSignature xmlSignature = xmlSigFac
				.unmarshalXMLSignature(validateContext);
		validateContext.setBaseURI(this.xml.getBaseURI());
		return xmlSignature;
	}

	/**
	 * Valida o contexto da assinatura com o valor da assinatura
	 * @param valid Indica se a assinatura é válida até o momento
	 * @param validateContext O contexto de validação do documento
	 * @param xmlSignature Objeto que representa a assinatura
	 * @return Indica se a validação foi válida
	 * @throws XMLSignatureException Exceção caso ocorra um erro durante a validação
	 */
	private boolean validateSignatureValue(boolean valid,
			DOMValidateContext validateContext, XMLSignature xmlSignature)
			throws XMLSignatureException {
		if (valid) {
			SignatureValue signatureValue = xmlSignature.getSignatureValue();
			valid = signatureValue.validate(validateContext);
		}
		return valid;
	}

	/**
	 * Valida a referência estando ela anexada ao documento (attached) ou destacada
	 * do documento (detached)
	 * @param validateContext O contexto de validação do documento
	 * @param reference A referência a ser validada
	 * @return Indica se a referência é válida
	 * @throws NoSuchAlgorithmException Exceção em caso de algoritmo inválido
	 * @throws IOException Exceção em caso de erro no cálculo de hash
	 * @throws URISyntaxException Exceção em caso de URI mal formada na referência
	 * @throws XMLSignatureException Exceção caso ocorra um erro durante a validação
	 */
	private boolean validateReferenceDetachedOrAttached(
			DOMValidateContext validateContext, Reference reference)
			throws NoSuchAlgorithmException, IOException, URISyntaxException, XMLSignatureException {
		boolean validReference = false;
		if (isDetached(reference.getURI())) {
			validReference = this.validateReference(reference);
		} else {
			try {
				// The ID attribute needs to be identified as such so that
				// reference.validate(validateContext) can work properly
				String uri = reference.getURI();
				if (uri != null && uri.length() != 0 && uri.charAt(0) == '#') {
					String id = uri.substring(1);

					XPath xpath = XPathFactory.newInstance().newXPath();
					NodeList referencedNodes = (NodeList) xpath.evaluate("//*[@Id='" + id + "']", this.xml, XPathConstants.NODESET);
					if (referencedNodes != null) {
						for (int i = 0; i < referencedNodes.getLength(); i++) {
							((Element)referencedNodes.item(i)).setIdAttribute("Id", true);
						}
					}
					referencedNodes = (NodeList) xpath.evaluate("//*[@ID='" + id + "']", this.xml, XPathConstants.NODESET);
					if (referencedNodes != null) {
						for (int i = 0; i < referencedNodes.getLength(); i++) {
							((Element)referencedNodes.item(i)).setIdAttribute("ID", true);
						}
					}
					referencedNodes = (NodeList) xpath.evaluate("//*[@id='" + id + "']", this.xml, XPathConstants.NODESET);
					if (referencedNodes != null) {
						for (int i = 0; i < referencedNodes.getLength(); i++) {
							((Element)referencedNodes.item(i)).setIdAttribute("id", true);
						}
					}
				}
			} catch (XPathExpressionException e) {
				Application.logger.log(Level.WARNING, "Erro na busca pelo atributo da tag que indica o identificador"
						+ "do conteúdo", e);
			}

			validReference = reference.validate(validateContext);
		}
		return validReference;
	}

	/**
	 * Verifica se a assinatura é destacada do documento
	 * @param uri A URI da referência
	 * @return Indica se a assinatura é destacada
	 */
	private boolean isDetached(String uri) {
		return uri.length() > 0 && uri.charAt(0) != '#';
	}

	/**
	 * Valida a referência da assinatura
	 * @param reference A referência a ser validada
	 * @return Indica se a referência é válida
	 * @throws NoSuchAlgorithmException Exceção caso o algoritmo seja inválido
	 * @throws IOException Exceção em caso de erro no cálculo de hash
	 * @throws URISyntaxException Exceção em caso de URI mal formada na referência
	 */
	private boolean validateReference(Reference reference)
			throws NoSuchAlgorithmException, IOException, URISyntaxException {
		byte[] referenceDigestValue = reference.getDigestValue();
		byte[] obtainedDigestValue = this.obtainDigestValue(reference);
		return MessageDigest.isEqual(referenceDigestValue, obtainedDigestValue);
	}

	/**
	 * Obtem o valor de hash de uma referência da assinatura
	 * @param reference A referência
	 * @return Os bytes de hash da referência dada
	 * @throws NoSuchAlgorithmException Exceção caso o algoritmo seja inválido
	 * @throws IOException Exceção em caso de erro no cálculo de hash
	 * @throws URISyntaxException Exceção em caso de URI mal formada na referência
	 */
	private byte[] obtainDigestValue(Reference reference)
			throws NoSuchAlgorithmException, IOException, URISyntaxException {
		// URI referenceUri = new URI(reference.getURI());
		// String absoluteUri = null;
		// if (!referenceUri.isAbsolute()) {
		// URI base = new URI(this.xml.getBaseURI());
		// File baseFile = new File(base.getPath());
		// String baseDirectory = null;
		// if (baseFile.isDirectory()) {
		// baseDirectory = baseFile.getPath() + File.separatorChar;
		// } else {
		// baseDirectory = baseFile.getParent() + File.separatorChar;
		// }
		// absoluteUri = baseDirectory + referenceUri.toString();
		// } else {
		// absoluteUri = referenceUri.toString();
		// }
		// InputStream bufferedInputStream = null;
		// bufferedInputStream = new FileInputStream(absoluteUri);
		// bufferedInputStream = new BufferedInputStream(bufferedInputStream);
		MessageDigest digester = MessageDigest.getInstance(AlgorithmIdentifierMapper
				.getAlgorithmNameFromIdentifier(reference.getDigestMethod()
						.getAlgorithm()));
		/* Lê todo o arquivo tirando o hash do mesmo */
		// byte[] bytes = new byte[1000];
		// int lenBytesRead = 0;
		// lenBytesRead = bufferedInputStream.read(bytes);
		// while (lenBytesRead > -1) {
		// digester.update(bytes, 0, lenBytesRead);
		// lenBytesRead = bufferedInputStream.read(bytes);
		// }
		byte[] obtainedDigestValue = new byte[0];
		String uri = reference.getURI();

		if (uri.startsWith("http") || uri.startsWith("https")) {
			try {
				URL url = new URL(uri);
				HttpURLConnection connection = (HttpURLConnection) url.openConnection();
				InputStream stream = connection.getInputStream();
				obtainedDigestValue = digester.digest(IOUtils.toByteArray(stream));
			} catch (IOException e) {
				e.printStackTrace();
			}
		} else {
			obtainedDigestValue = digester.digest(this.container.getContent());
		}

		return obtainedDigestValue;
	}

	/**
	 * Retorna a assinatura em forma de {@link Document} para que se possa
	 * navegar por ela mais livremente.
	 * Obs.: A referência interna é passada, por isso se for causado algum erro
	 * na assinatura através do document, esse erros posteriomente aparecerão
	 * dentro do {@link XadesSignature} também.
	 * @return A assinatura na representação DOM
	 */
	public Document getXml() {
		return this.xml;
	}

	/**
	 * Retorna a lista de atributos presente na assinatura.
	 * @return A lista de atributos na assinatura
	 */
	public List<String> getAttributeList() throws ClassCastException {
		List<String> attributeList = new ArrayList<String>();
		NodeList signedSignatureObjectList = this.signatureElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						SIGNED_SIGNATURE_PROPERTIES);
		if (signedSignatureObjectList.getLength() > 0) {
			NodeList signedSignatureAttrs =
					signedSignatureObjectList.item(0).getChildNodes();
			for (int i = 0; i < signedSignatureAttrs.getLength(); i++) {
				Element attrElement = (Element) signedSignatureAttrs.item(i);
				attributeList.add(attrElement.getTagName().substring(
						attrElement.getTagName().indexOf(COLON) + 1));
			}
		}
		NodeList signedDataObjectList = this.signatureElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						SIGNED_DATA_OBJECT_PROPERTIES);
		if (signedDataObjectList.getLength() > 0) {
			NodeList signedDataObjectAttrs = signedDataObjectList.item(0)
					.getChildNodes();
			for (int i = 0; i < signedDataObjectAttrs.getLength(); i++) {
				Element attrElement = (Element) signedDataObjectAttrs.item(i);
				attributeList.add(attrElement.getTagName().substring(
						attrElement.getTagName().indexOf(COLON) + 1));
			}
		}
		NodeList unsignedSignatureProperties = this.signatureElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						UNSIGNED_SIGNATURE_PROPERTIES);
		if (unsignedSignatureProperties.getLength() > 0) {
			NodeList unsignedSignatureAttrs = unsignedSignatureProperties.item(
					0).getChildNodes();
			for (int i = 0; i < unsignedSignatureAttrs.getLength(); i++) {
				Element attrElement = (Element) unsignedSignatureAttrs.item(i);
				attributeList.add(attrElement.getTagName().substring(
						attrElement.getTagName().indexOf(COLON) + 1));
			}
		}
		NodeList unsignedDataObjectProperties = this.signatureElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						UNSIGNED_DATA_OBJECT_PROPERTIES);
		if (unsignedDataObjectProperties.getLength() > 0) {
			NodeList unsignedDataObjectAttrs = unsignedDataObjectProperties
					.item(0).getChildNodes();
			for (int i = 0; i < unsignedDataObjectAttrs.getLength(); i++) {
				Element attrElement = (Element) unsignedDataObjectAttrs.item(i);
				attributeList.add(attrElement.getTagName().substring(
						attrElement.getTagName().indexOf(COLON) + 1));
			}
		}
		return attributeList;
	}

	/**
	 * Retorna o atributo correspondente ao identificador dado
	 * @param attributeId O identificador do atributo
	 * @param index O índice do atributo
	 * @return O atributo correspondente ao identificador dado
	 * @throws SignatureAttributeNotFoundException Exceção caso o atributo não seja encontrado
	 */
	public Element getEncodedAttribute(String attributeId, Integer index)
			throws SignatureAttributeNotFoundException {
		if (index < 0) {
			throw new SignatureAttributeNotFoundException(
					SignatureAttributeNotFoundException.INDEX_OUT_OF_BOUNDS);
		}
		NodeList attributeNodeList = this.signatureElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						attributeId);
		if (attributeNodeList.getLength() <= index) {
			attributeNodeList = this.signatureElement
					.getElementsByTagNameNS(NamespacePrefixMapperImp.XADESv141_NS,
							attributeId);
			if (attributeNodeList.getLength() <= index) {
				throw new SignatureAttributeNotFoundException(
						SignatureAttributeNotFoundException.ATTRIBUTE_NOT_FOUND
								+ attributeId);
			}
		}
		Element attributeElement = (Element) attributeNodeList.item(index);
		return attributeElement;
	}

	/**
	 * Retorna o primeiro atributo da assinatura
	 * @param attributeId O identificador do atributo
	 * @return O primeiro  atributo da assinatura
	 * @throws SignatureAttributeNotFoundException
	 */
	public Element getEncodedAttribute(String attributeId)
			throws SignatureAttributeNotFoundException {
		return this.getEncodedAttribute(attributeId, 0);
	}

	/**
	 * Retorna o identificador da política de assinatura
	 * @return O identificador da política de assinatura
	 */
	public String getSignaturePolicyIdentifier() {
		Element signaturePolicyIdentifierElement = (Element) this.signatureElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						SIGNATURE_POLICY_IDENTIFIER).item(0);
		Element sigPolIdElement = (Element) signaturePolicyIdentifierElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						"SigPolicyId").item(0);
		Element identifierElement = (Element) sigPolIdElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						"Identifier").item(0);
		return identifierElement.getTextContent();
	}

	/**
	 * Verifica se o conteúdo assinado é externo
	 * @return Indica se o conteúdo assinado é externo
	 */
	public boolean isExternalSignedData() {
		boolean result = false;
		NodeList referenceList = this.signatureElement
				.getElementsByTagName(DS_REFERENCE);
		Node tempNode;
		for (int i = 0; i < referenceList.getLength(); i++) {
			tempNode = referenceList.item(i);
			if (tempNode.getAttributes().getNamedItem(TYPE) == null) {
				result |= isExternalReference(tempNode);
			}
		}
		return result;
	}

	/**
	 * Retorna o valor de hash da assinatura
	 * @param algorithm O algoritmo a ser utilizado para o cálculo de hash
	 * @return Array de bytes com valor de hash da assinatura
	 * @throws PbadException Exceção em caso de erro no cálculo
	 */
	public byte[] getSignatureValueHash(String algorithm) throws PbadException {
		byte[] bytes = this.getSignatureBytes();
		return Canonicalizator.getHash(algorithm, bytes);
	}

	/**
	 * Retorna o hash concatenado da assinatura, com o hash do carimbo do tempo,
	 * com o hash das referências do certificado, com o hash das referências de
	 * revogação.
	 * @param algorithm O algoritmo a ser utilizado para o cálculo de hash
	 * @return Array de bytes com valor de hash
	 * @throws PbadException Exceção em caso de erro no cálculo
	 */
	public byte[] getSigAndRefsHashValue(String algorithm) throws PbadException {
		byte[] concatenedBytes = null;
		byte[] signatureBytes = this.getSignatureBytes();
		byte[] signatureTimeStampBytes = this.getSignatureTimeStampBytes();
		byte[] certificateRefsBytes = this.getCertificatesRefsBytes();
		byte[] revocationRefsBytes = this.getRevocationRefsBytes();
		concatenedBytes = concatenateBytes(signatureBytes,
				signatureTimeStampBytes);
		concatenedBytes = concatenateBytes(concatenedBytes,
				certificateRefsBytes);
		concatenedBytes = concatenateBytes(concatenedBytes, revocationRefsBytes);
		if (this.hasAttributesRefs()) {
			byte[] attributeCertificateBytes = this
					.getAttributeCertificateBytes();
			byte[] attributeRevocationRefsBytes = this
					.getAttributeRevocationBytes();
			concatenedBytes = concatenateBytes(concatenedBytes,
					attributeCertificateBytes);
			concatenedBytes = concatenateBytes(concatenedBytes,
					attributeRevocationRefsBytes);
		}
		return Canonicalizator.getHash(algorithm, concatenedBytes);
	}

	/**
	 * Retorna os bytes da assinatura
	 * @return Os bytes da assinatura
	 * @throws SignatureAttributeException Exceção em caso de erro na canonização do valor
	 */
	private byte[] getSignatureBytes() throws SignatureAttributeException {
		// Apenas o nodo signatureValue é necessário aqui
		Node signatureValue = this.getSignatureElement()
				.getElementsByTagName("ds:SignatureValue").item(0);
		if (signatureValue == null) {
			signatureValue = this.getSignatureElement()
					.getElementsByTagName("SignatureValue").item(0);
		}
		return this.getCanonicalizedFormBytes(signatureValue);
	}

	/**
	 * Retorna os bytes da assinatura em forma canônica
	 * @param signatureValue O nodo que contém a assinatura
	 * @return Os bytes da assinatura em forma canônica
	 * @throws SignatureAttributeException Exceção em caso de erro na canonização do valor
	 */
	private byte[] getCanonicalizedFormBytes(Node signatureValue)
			throws SignatureAttributeException {
		OctetStreamData transformedXml = Canonicalizator.getCanonicalization(
				signatureValue, this.canonicalizationMethodAlgorithm);
		InputStream stream = transformedXml.getOctetStream();
		byte[] bytes = new byte[0];
		try {
			bytes = IOUtils.toByteArray(stream);
		} catch (IOException ioException) {
			throw new SignatureAttributeException(ioException.getMessage(),
					ioException.getStackTrace());
		}
		return bytes;
	}

	/**
	 * Concatena bytes
	 * @param first Os bytes iniciais
	 * @param second Os bytes finais
	 * @return Os dois arrays de bytes concatenados
	 */
	private byte[] concatenateBytes(byte[] first, byte[] second) {
		byte[] result = null;
		if (first == null)
			result = second;
		else {
			result = new byte[first.length + second.length];
			System.arraycopy(first, 0, result, 0, first.length);
			System.arraycopy(second, 0, result, first.length + 0, second.length);
		}
		return result;
	}

	/**
	 * Retorna o atributo de revogação em bytes
	 * @return O atributo de revogação em bytes
	 * @throws PbadException Exceção em caso de erro na canonização
	 */
	private byte[] getAttributeRevocationBytes() throws PbadException {
		return this.getAttributesCanonicalizedBytes(ATTRIBUTE_REVOCATION_REFS);
	}

	/**
	 * Retorna o certificado de atributo em bytes
	 * @return O certificado de atributo em bytes
	 * @throws PbadException Exceção em caso de erro na canonização
	 */
	private byte[] getAttributeCertificateBytes() throws PbadException {
		return this.getAttributesCanonicalizedBytes(ATTRIBUTE_CERTIFICATE_REFS);
	}

	/**
	 * Verifica se os atributos tem referência
	 * @return Indica a presença de referência entre os atributos
	 */
	private boolean hasAttributesRefs() {
		List<String> attributeIdentifiers = this.getAttributeList();
		return attributeIdentifiers.contains(ATTRIBUTE_CERTIFICATE_REFS);
	}

	/**
	 * Retorna as referências em bytes de revogação
	 * @return O array de bytes das referências de revogação
	 * @throws PbadException Exceção em caso de erro na canonização
	 */
	private byte[] getRevocationRefsBytes() throws PbadException {
		return this.getAttributesCanonicalizedBytes(COMPLETE_REVOCATION_REFS);
	}

	/**
	 * Retorna as referências em bytes da estrutura certificates
	 * @return O array de bytes das referências da estrutura certificates
	 * @throws PbadException Exceção em caso de erro na canonização
	 */
	private byte[] getCertificatesRefsBytes() throws PbadException {
		return this.getAttributesCanonicalizedBytes(COMPLETE_CERTIFICATE_REFS);
	}

	/**
	 * Retorna o carimbo do tempo da assinatura em bytes.
	 * @return O array de bytes do carimbo do tempo da assinatura
	 * @throws PbadException Exceção em caso de erro na canonização
	 */
	private byte[] getSignatureTimeStampBytes() throws PbadException {
		return this.getAttributesCanonicalizedBytes(SIGNATURE_TIME_STAMP);
	}

	/**
	 * Retorna em bytes o atributo em forma canônica
	 * @param attributeIdentifier O identificador do atributo
	 * @return O array de bytes do atributo em forma canônica
	 * @throws PbadException Exceção em caso de erro na canonização
	 */
	private byte[] getAttributesCanonicalizedBytes(String attributeIdentifier)
			throws PbadException {
		byte[] result = null;
		List<String> attributesIdentifiers = this.getAttributeList();
		if (!attributesIdentifiers.contains(attributeIdentifier)) {
			throw new PbadException("Não existe o atributo "
					+ attributeIdentifier + " para que se possa obter os bytes");
		}
		int i = 0;
		boolean hasMoreTimeStamps = true;
		attributesIdentifiers.remove(attributeIdentifier);
		while (hasMoreTimeStamps) {
			Element timeStampEncoded = this.getEncodedAttribute(
					attributeIdentifier, i++);
			Element timeStampElement = timeStampEncoded;
			if (result == null) {
				result = this.getCanonicalizedFormBytes(timeStampElement);
			} else {
				byte[] canonicalizedTimeStamp = this
						.getCanonicalizedFormBytes(timeStampElement);
				result = this.concatenateBytes(result, canonicalizedTimeStamp);
			}
			hasMoreTimeStamps = attributesIdentifiers
					.remove(attributeIdentifier);
		}
		return result;
	}

	/**
	 * Verifica se há referência externa no nodo
	 * @param tempNode O nodo a ser verificado
	 * @return Indica se o nodo possui referência externa
	 */
	private boolean isExternalReference(Node tempNode) {
		boolean result = true;
		String uri;
		uri = (tempNode.getAttributes().getNamedItem("URI").getTextContent());
		if (uri.length() > 0 && uri.charAt(0) == '#') {
			result = false;
		} else {
			if (uri.length() == 0)
				result = false;
		}
		return result;
	}

	/**
	 * Adiciona um atributo à lista de atributos não-assinados
	 * @param attribute O atributo a ser adicionado
	 * @throws DOMException Exceção em caso de erro na estrutura do XML
	 * @throws EncodingException
	 * @throws XadesSignatureContainerException Exceção em caso de erro no processo de marshall
	 * @throws SignatureAttributeException Exceção em caso de erro no atributo
	 */
	public void addUnsignedAttribute(SignatureAttribute attribute)
			throws DOMException, EncodingException,
			XadesSignatureContainerException, SignatureAttributeException {

		NodeList unsignedPropertiesNodeList = this.getSignatureElement()
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						UNSIGNED_SIGNATURE_PROPERTIES);
		boolean attributeIsSigned = attribute.isSigned();
		if (!attributeIsSigned) {
			List<String> attributeIdentifiers = this.getAttributeList();
			int ocurrences = 0;
			if (attribute.isUnique()) {
				for (String identifier : attributeIdentifiers) {
					if (identifier.equals(attribute.getIdentifier()))
						ocurrences++;
				}
			}
			if (ocurrences == 0) {
				if (unsignedPropertiesNodeList.getLength() == 0) {
					Element qualifyingPropertiesElement = (Element) this
							.getSignatureElement()
							.getElementsByTagNameNS(
									NamespacePrefixMapperImp.XADES_NS,
									QUALIFYING_PROPERTIES).item(0);
					try {
						Marshaller
								.marshallUnsignedProperties(qualifyingPropertiesElement);
					} catch (XmlProcessingException xmlProcessingException) {
						throw new XadesSignatureContainerException(
								xmlProcessingException);
					}
					unsignedPropertiesNodeList = this.getSignatureElement()
							.getElementsByTagNameNS(
									NamespacePrefixMapperImp.XADES_NS,
									UNSIGNED_SIGNATURE_PROPERTIES);
				}
				Node importedNode = unsignedPropertiesNodeList.item(0)
						.getOwnerDocument()
						.importNode(attribute.getEncoded(), true);
				unsignedPropertiesNodeList.item(0).appendChild(importedNode);
			} else {
				throw new UniqueAttributeException(
						UniqueAttributeException.DUPLICATED_ATTRIBUTE
								+ attribute.getIdentifier());
			}
		} else {
			throw new SignatureAttributeException(
					SignatureAttributeException.STRUCTURE_VIOLATION);
		}
	}

	/**
	 * Retorna a contra-assinatura
	 * @param signerCertificate O certificado do assinante
	 * @return A contra-assinatura ou nulo caso não seja encontrada
	 * @throws CounterSignatureException Exceção em caso de problema com o certificado na contra-assinatura
	 */
	public CounterSignatureInterface getCounterSignature(
			X509Certificate signerCertificate) throws CounterSignatureException {
		CounterSignature counterSignature = null;

		List<CounterSignatureInterface> counterSignatures = this
				.getCounterSignatures();
		int i = 0;
		boolean found = false;

		while (i < counterSignatures.size() && !found) {

			CounterSignature actualCounterSignature = (CounterSignature) counterSignatures
					.get(i);
			SigningCertificate actualSigningCertificate = null;
			try {
				actualSigningCertificate = new SigningCertificate(
						actualCounterSignature
								.getEncodedAttribute(SigningCertificate.IDENTIFIER));
			} catch (SignatureAttributeNotFoundException signatureAttributeNotFoundException) {
				throw new CounterSignatureException(
						"Problemas para encontrar o SigningCertificate dentro de uma contra-assinatura",
						signatureAttributeNotFoundException);
			} catch (EncodingException encodingException) {
				throw new CounterSignatureException(
						"Problemas ao decodificar um certificado de uma contra-assinatura",
						encodingException);
			}
			found = actualSigningCertificate.match(signerCertificate);

			if (found) {
				counterSignature = actualCounterSignature;
			} else {
				List<CounterSignatureInterface> counterSignaturesInCounterSignature = actualCounterSignature
						.getCounterSignatures();
				if (counterSignaturesInCounterSignature != null
						&& counterSignaturesInCounterSignature.size() > 0) {
					CounterSignature foundedCounterSignature = (CounterSignature) getCounterSignature(
							signerCertificate,
							counterSignaturesInCounterSignature);
					if (foundedCounterSignature != null) {
						found = true;
						counterSignature = foundedCounterSignature;
					}
				}
			}
			i++;
		}

		if (counterSignature == null)
			throw new CounterSignatureException(
					CounterSignatureException.SIGNING_CERTIFICATE_NOT_FOUND);

		return counterSignature;
	}

	/**
	 * Procura uma contra-assinatura entre a lista de contra-assinaturas
	 * @param signerCertificate O certificado do assinante
	 * @param counterSignatures A lista de contra-assinaturas
	 * @return A contra-assinatura ou nulo caso não seja encontrada
	 * @throws CounterSignatureException Exceção em caso de problema com o certificado na contra-assinatura
	 */
	private CounterSignatureInterface getCounterSignature(
			X509Certificate signerCertificate,
			List<CounterSignatureInterface> counterSignatures)
			throws CounterSignatureException {
		CounterSignature counterSignature = null;

		int i = 0;
		boolean found = false;

		while (i < counterSignatures.size() && !found) {

			CounterSignature actualCounterSignature = (CounterSignature) counterSignatures
					.get(i);
			SigningCertificate actualSigningCertificate = null;
			try {
				actualSigningCertificate = new SigningCertificate(
						actualCounterSignature
								.getEncodedAttribute(SigningCertificate.IDENTIFIER));
			} catch (SignatureAttributeNotFoundException signatureAttributeNotFoundException) {
				throw new CounterSignatureException(
						"Problemas para encontrar o SigningCertificate dentro de uma contra-assinatura",
						signatureAttributeNotFoundException);
			} catch (EncodingException encodingException) {
				throw new CounterSignatureException(
						"Problemas ao decodificar um certificado de uma contra-assinatura",
						encodingException);
			}
			found = actualSigningCertificate.match(signerCertificate);

			if (found)
				counterSignature = actualCounterSignature;
			else {
				List<CounterSignatureInterface> counterSignaturesInCounterSignature = actualCounterSignature
						.getCounterSignatures();
				if (counterSignaturesInCounterSignature != null
						&& counterSignaturesInCounterSignature.size() > 0) {
					CounterSignature foundedCounterSignature = (CounterSignature) getCounterSignature(
							signerCertificate,
							counterSignaturesInCounterSignature);
					if (foundedCounterSignature != null) {
						found = true;
						counterSignature = foundedCounterSignature;
					}
				}
			}
			i++;
		}

		return counterSignature;
	}

	/**
	 * Retorna uma lista de contra-assinatura
	 * @return A lista de contra-assinaturas
	 */
	public List<CounterSignatureInterface> getCounterSignatures() {
		List<CounterSignatureInterface> counterSignatures = new ArrayList<CounterSignatureInterface>();
		NodeList unsignedSignatureProperties = this.signatureElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						UNSIGNED_SIGNATURE_PROPERTIES);
		if (unsignedSignatureProperties != null
				&& unsignedSignatureProperties.getLength() > 0) {
			NodeList childNodes = unsignedSignatureProperties.item(0)
					.getChildNodes();
			for (int i = 0; i < childNodes.getLength(); i++) {
				if (childNodes.item(i).getNodeName()
						.equals(XADES_COUNTER_SIGNATURE)) {
					Element counterSignatureElement = (Element) childNodes
							.item(i);
					Element signatureElement = (Element) counterSignatureElement
							.getElementsByTagNameNS(
									NamespacePrefixMapperImp.XMLDSIG_NS,
									"Signature").item(0);
					CounterSignatureInterface counterSignatureAttribute = new CounterSignature(
							counterSignatureElement.getOwnerDocument(),
							signatureElement);
					counterSignatures.add(counterSignatureAttribute);
				}
			}
		}
		return counterSignatures;
	}

	/**
	 * Verifica se o nodo de certificado e o objeto de certificado
	 * são da mesma entidade
	 * @param signingCertificateElement Um nodo de certificado
	 * @param signerCertificate Um certificado
	 * @return Indica se o certificado dos dois elementos pertencem
	 * à mesma entidade
	 */
	protected boolean isEqualsSignerId(Element signingCertificateElement,
			X509Certificate signerCertificate) {
		boolean isEqualsSignerId = false;
		SignerId counterSignerId = this.buildSignerIdentifier(
				signerCertificate.getIssuerX500Principal(),
				signerCertificate.getSerialNumber());
		Element certElement = (Element) signingCertificateElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						"Cert").item(0);
		Element issuerSerial = (Element) certElement.getElementsByTagNameNS(
				NamespacePrefixMapperImp.XADES_NS, "IssuerSerial").item(0);
		String issuerName = issuerSerial.getChildNodes().item(0)
				.getTextContent();
		String serialNumber = issuerSerial.getChildNodes().item(1)
				.getTextContent();
		SignerId temporary = this.buildSignerIdentifier(new X500Principal(
				issuerName), new BigInteger(serialNumber));
		if (counterSignerId.equals(temporary)) {
			isEqualsSignerId = true;
		}
		return isEqualsSignerId;
	}

	/**
	 * Constrói um objeto da classe {@link SignerId}.
	 * @param issuerName Nome do emissor do certificado
	 * @param serialNumber Número do serial do certificado
	 * @return O {@link SignerId} gerado
	 */
	protected SignerId buildSignerIdentifier(X500Principal issuerName,
			BigInteger serialNumber) {
		X500Name x500Name = new X500Name(issuerName.getName());
		SignerId signerId = new SignerId(x500Name, serialNumber);
		return signerId;
	}

	/**
	 * Verifica se existe a propriedade SigningCertificate na contra assinatura
	 * @param counterSignature A contra assinatura
	 * @return Indica se existe a propriedade SigningCertificate
	 */
	protected boolean hasSigningCertificate(CounterSignature counterSignature) {
		Element signingCertificateElement = (Element) counterSignature
				.getSignatureElement()
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						SIGNING_CERTIFICATE).item(0);
		return signingCertificateElement != null;
	}

	/**
	 * Obtém o valor do atributo Id da tag SignatureValue
	 * @return Valor do atributo Id da tag SignatureValue
	 */
	public String getSignatureValueAttribute() {
		Element signatureValueElement = (Element) this.signatureElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS,
						SIGNATURE_VALUE).item(0);
		return signatureValueElement.getAttribute(ID);
	}

	/**
	 * Substitui um atributo não-assinado
	 * @param attribute O novo valor do atributo não-assinado
	 * @param index O índice do atributo a ser substituído
	 * @throws SignatureAttributeException Exceção em caso de erro na manipulação dos atributos
	 */
	public void replaceUnsignedAttribute(SignatureAttribute attribute, Integer index) throws SignatureAttributeException {
		String attributeIdentifier = attribute.getIdentifier();
		Element attributeEncoded = attribute.getEncoded();
		Element newAttribute = (Element) this.xml.importNode(attributeEncoded,
				true);
		Element oldAttribute = (Element) this.signatureElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						attributeIdentifier).item(index);
		Element parent = (Element) oldAttribute.getParentNode();
		parent.replaceChild(newAttribute, oldAttribute);
	}

	/**
	 * Retorna o formato da assinatura.
	 * @return Formato XAdES
	 */
	public SignatureFormat getFormat() {
		return SignatureFormat.XAdES;
	}

	/**
	 * Retorna o modo de assinatura contido na assinatura
	 * @return O modo de assinatura
	 * @throws SignatureModeException Exceção caso seja um modo inválido
	 */
	public ContainedSignatureMode getMode() throws SignatureModeException {
		NodeList referenceList = this.signatureElement
				.getElementsByTagName(DS_REFERENCE);
		Node referenceNode;
		Node tempNode;
		String uri = null;
		boolean isDetached = false;
		boolean isEnveloping = false;
		boolean isEnveloped = false;
		for (int i = 0; i < referenceList.getLength(); i++) {
			referenceNode = referenceList.item(i);
			tempNode = referenceNode.getAttributes().getNamedItem(TYPE);
			if (tempNode != null) {
				if (!tempNode.getTextContent().contains(SIGNED_PROPERTIES)) {
					uri = referenceNode.getAttributes().getNamedItem("URI")
							.getTextContent();
				}
			} else {
				tempNode = referenceNode.getAttributes().getNamedItem(ID);
				uri = referenceNode.getAttributes().getNamedItem("URI")
						.getTextContent();
			}
			if (uri != null) {
				if (uri.equals("")) {
					isEnveloped = true;
				} else if (uri.substring(0, 3).compareTo("#id") == 0) {
					if (this.isEnveloped(uri)) {
						isEnveloped = true;
					} else {
						isEnveloping = true;
					}
				} else {
					isDetached = true;
				}
			}
		}
		ContainedSignatureMode signatureMode = null;
		if (isDetached) {
			signatureMode = ContainedSignatureMode.DETACHED;
			if (isEnveloped) {
				signatureMode = ContainedSignatureMode.DETACHED_ENVELOPED;
				if (isEnveloping) {
					signatureMode = ContainedSignatureMode.DETACHED_ENVELOPING_ENVELOPED;
				}
			}
			if (isEnveloping) {
				signatureMode = ContainedSignatureMode.DETACHED_ENVELOPING;
			}
		} else if (isEnveloped) {
			signatureMode = ContainedSignatureMode.ENVELOPED;
			if (isEnveloping) {
				signatureMode = ContainedSignatureMode.ENVELOPING_ENVELOPED;
			}
		} else if (isEnveloping) {
			signatureMode = ContainedSignatureMode.ENVELOPING;
		}
		if (signatureMode == null) {
			throw new SignatureModeException(
					SignatureModeException.INVALID_MODE);
		}
		return signatureMode;
	}

	/**
	 * Verifica se a assinatura é do modo "enveloped"
	 * @param uri A URI de uma referência
	 * @return Indica se é "enveloped"
	 */
	private boolean isEnveloped(String uri) {
		boolean isEnveloped = true;
		uri = uri.substring(1);
		String id = null;
		Element objectElement = null;
		NodeList objectsList = this.signatureElement
				.getElementsByTagName("ds:Object");
		for (int i = 0; i < objectsList.getLength(); i++) {
			objectElement = (Element) objectsList.item(i);
			id = objectElement.getAttribute(ID);
			if (id.compareTo("") != 0) {
				if (id.compareTo(uri) == 0) {
					isEnveloped = false;
				}
			}
		}
		return isEnveloped;
	}

	/**
	 * Retorna a URI da política de assinatura
	 * @return A URI da política de assinatura
	 */
	public String getSignaturePolicyUri() {
		Element signaturePolicyIdentifierElement = (Element) this.signatureElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						SIGNATURE_POLICY_IDENTIFIER).item(0);
		Element sigPolIdElement = (Element) signaturePolicyIdentifierElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						SIG_POLICY_QUALIFIERS).item(0);
		Element identifierElement = (Element) sigPolIdElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						SPURI).item(0);
		return identifierElement.getTextContent();
	}

	/**
	 * Retorna o valor de hash no nodo da política de assinatura
	 * @return O hash da política de assinatura
	 */
	public String getSignaturePolicyHashValue() {
		NodeList nodeList = this.signatureElement.getElementsByTagNameNS(
				NamespacePrefixMapperImp.XADES_NS, SIGNATURE_POLICY_IDENTIFIER);
		Node signaturePolicyIdentifierNode = nodeList.item(0);
		NodeList signaturePolicyIdentifierNodeList = signaturePolicyIdentifierNode
				.getChildNodes();
		Node signaturePolicyIdNode = signaturePolicyIdentifierNodeList.item(0);
		NodeList signaturePolicyIdNodeList = signaturePolicyIdNode
				.getChildNodes();
		Node sigPolicyHashNode = signaturePolicyIdNodeList.item(1);
		NodeList sigPolicyHashNodeList = sigPolicyHashNode.getChildNodes();
		Node digestValueNode = sigPolicyHashNodeList.item(1);
		return digestValueNode.getTextContent();
	}

	/**
	 * Remove o nodo do atributo não-assinado no arquivo
	 * @param attributeId O identificador do atributo a ser removido
	 * @param index O índice do atributo
	 * @throws SignatureAttributeException Exceção caso o atributo não seja encontrado
	 * @throws EncodingException
	 */
	public void removeUnsignedAttribute(String attributeId, int index)
			throws SignatureAttributeException, EncodingException {
		Element attributeToRemove = this
				.getEncodedAttribute(attributeId, index);
		NodeList unsignedPropertiesNodeList = this.getSignatureElement()
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						UNSIGNED_SIGNATURE_PROPERTIES);
		if (unsignedPropertiesNodeList.getLength() == 0) {
			throw new SignatureAttributeException(
					SignatureAttributeException.ATTRIBUTE_NOT_FOUND);
		}
		Element unsignedSignatureProperties = (Element) unsignedPropertiesNodeList
				.item(0);
		unsignedSignatureProperties.removeChild(attributeToRemove);
		Node parentNode = unsignedSignatureProperties.getParentNode();
		if (!unsignedSignatureProperties.hasChildNodes()) {
			parentNode.removeChild(unsignedSignatureProperties);
		}
		if (!parentNode.hasChildNodes()) {
			parentNode.getParentNode().removeChild(parentNode);
		}
	}

	/**
	 * Calcula o valor de hash do carimbo de tempo de arquivamento
	 * @param hashAlgorithmName O algoritmo a ser utilizado no cálculo
	 * @return O valor de hash do carimbo
	 * @throws PbadException Exceção em caso de erro na canonização
	 */
	public byte[] getArchiveTimeStampHashValue(String hashAlgorithmName)
			throws PbadException {
		return this.getArchiveTimeStampHashValue(hashAlgorithmName, null);
	}

	/**
	 * Calcula o valor de hash do carimbo de tempo de arquivamento
	 * @param hashAlgorithmName O algoritmo a ser utilizado no cálculo
	 * @param time O horário do carimbo
	 * @return O valor de hash do carimbo
	 * @throws PbadException Exceção em caso de erro na canonização
	 */
	public byte[] getArchiveTimeStampHashValue(String hashAlgorithmName,
			Time time) throws PbadException {
		ByteArrayOutputStream octetStream = new ByteArrayOutputStream();
		this.calculateArchiveTimeStampHashValue(octetStream, time);
		byte[] concatenatedBytes = octetStream.toByteArray();
		return Canonicalizator.getHash(hashAlgorithmName, concatenatedBytes);
	}

	/**
	 * Passos para cálculo do hash do carimbo do tempo de arquivamento, conforme
	 * o documento ETSI TS 101 903 V1.4.1 (2009-06) seção 8.2.1
	 * @param octetStream Onde está sendo escrito os bytes contatenados do hash
	 * @param time A data do carimbo do tempo
	 * @throws SignatureAttributeException Exceção em caso de erro nos atributos da assinatura
	 * @throws EncodingException Exceção em caso de erro na canonização
	 */
	protected void calculateArchiveTimeStampHashValue(OutputStream octetStream,
			Time time) throws SignatureAttributeException, EncodingException {
		// O primeiro passo está sendo desconsiderado pois é apenas a
		// instanciação do objeto octetStrem
		this.secondStepToComputationDisgestValue(octetStream);
		this.thirdStepToComputationDisgestValue(octetStream);
		if (time != null)
			this.fourthStepToComputationDisgestValueWithDate(octetStream, time);
		else {
			this.fourthStepToComputationDisgestValue(octetStream);
		}
		this.fifthStepToComputationDisgestValue(octetStream);
	}

	/**
	 * Obtém todos os elementos ds:Reference presentes no elemento
	 * ds:SignedInfo, independente de quem for o signatário. Canonicaliza cada
	 * nodo obtido e concatena o hash de cada um ao octet stream final. ETSI TS
	 * 101 903 V1.4.1 (2009-06) seção 8.2.1 (segundo passo)
	 * @param octetStream Os bytes para o cálculo do hash do carimbo de arquivamento
	 * @throws SignatureAttributeException Exceção em caso de erro na canonização
	 */
	private void secondStepToComputationDisgestValue(OutputStream octetStream)
			throws SignatureAttributeException {
		NodeList signerInfoNodeList = (NodeList) signatureElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS,
						SIGNED_INFO).item(0);
		for (int i = 0; i < signerInfoNodeList.getLength(); i++) {
			if (signerInfoNodeList.item(i).getLocalName().equals(REFERENCE)) {
				Node referenceNode = (Node) signerInfoNodeList.item(i);
				Canonicalizator.canonicalizationAndConcatenate(referenceNode,
						octetStream, this.canonicalizationMethodAlgorithm);
			}
		}
	}

	/**
	 * Obtém os elementos ds:SignedInfo, ds:SignatureValue, e ds:KeyInfo (se
	 * presente), e nesta ordem canonicaliza cada um e concatena cada hash ao
	 * octet stream final. ETSI TS 101 903 V1.4.1 (2009-06) seção 8.2.1
	 * (terceiro passo)
	 * @param octetStream Os bytes para o cálculo do hash do carimbo de arquivamento
	 * @throws SignatureAttributeException Exceção em caso de erro na canonização
	 */
	private void thirdStepToComputationDisgestValue(OutputStream octetStream)
			throws SignatureAttributeException {
		Node signerInfoNode = signatureElement.getElementsByTagNameNS(
				NamespacePrefixMapperImp.XMLDSIG_NS, SIGNED_INFO).item(0);
		Canonicalizator.canonicalizationAndConcatenate(signerInfoNode,
				octetStream, this.canonicalizationMethodAlgorithm);
		Node signatureValueNode = signatureElement.getElementsByTagNameNS(
				NamespacePrefixMapperImp.XMLDSIG_NS, SIGNATURE_VALUE).item(0);
		Canonicalizator.canonicalizationAndConcatenate(signatureValueNode,
				octetStream, this.canonicalizationMethodAlgorithm);
		Node keyInfoNode = signatureElement.getElementsByTagNameNS(
				NamespacePrefixMapperImp.XMLDSIG_NS, "KeyInfo").item(0);
		if (keyInfoNode != null) {
			Canonicalizator.canonicalizationAndConcatenate(signatureValueNode,
					octetStream, this.canonicalizationMethodAlgorithm);
		}
	}

	/**
	 * Obtém as propriedades não assinadas e canonicaliza cada uma e concatena o
	 * hash de cada uma ao octet stream final. Se as propriedades não assinadas
	 * RevocationValues ou CertificateValues não estiverem presentes é gerada
	 * uma exceção informando para adicioná-las. ETSI TS 101 903 V1.4.1
	 * (2009-06) seção 8.2.1 (quarto passo)
	 * @param octetStream Os bytes para o cálculo do hash do carimbo de arquivamento
	 * @throws SignatureAttributeException Exceção em caso de erro na canonização
	 */
	private void fourthStepToComputationDisgestValue(OutputStream octetStream)
			throws SignatureAttributeException {
		Node certificateValuesPropertiesNode = signatureElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						CERTIFICATE_VALUES).item(0);
		if (certificateValuesPropertiesNode == null) {
			throw new SignatureAttributeException(
					SignatureAttributeException.MISSING_CERTIFICATE_VALUES);
		}
		Node revocationValuesPropertiesNode = signatureElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						REVOCATION_VALUES).item(0);
		if (revocationValuesPropertiesNode == null) {
			throw new SignatureAttributeException(
					SignatureAttributeException.MISSING_REVOCATION_VALUES);
		}
		Node unsignedPropertiesNode = signatureElement.getElementsByTagNameNS(
				NamespacePrefixMapperImp.XADES_NS, UNSIGNED_PROPERTIES).item(0);
		if (unsignedPropertiesNode != null) {
			NodeList unsignedSignatureProperties = (NodeList) signatureElement
					.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
							UNSIGNED_SIGNATURE_PROPERTIES).item(0);
			for (int i = 0; i < unsignedSignatureProperties.getLength(); i++) {
				Element nodeValue = (Element) unsignedSignatureProperties
						.item(i);
				Canonicalizator.canonicalizationAndConcatenate(nodeValue,
						octetStream, this.canonicalizationMethodAlgorithm);
			}
		} else {
			throw new SignatureAttributeException(
					SignatureAttributeException.UNSIGNED_PROPERTIES_NOT_FOUND);
		}
	}

	/**
	 * Quarto passo utilizado somente para validação da assinatura. O argumento
	 * 'time' serve para não incluir no calculo do hash qualquer carimbo
	 * que tenha sido adicionado após o carimbo que está sendo validado no
	 * momento. ETSI TS 101 903 V1.4.1 (2009-06) seção 8.2.1 (quarto passo)
	 * @param octetStream Os bytes para o cálculo do hash do carimbo de arquivamento
	 * @param time Horário que o carimbo de arquivamento foi criado
	 * @throws SignatureAttributeException
	 * @throws EncodingException Exceção em caso de erro na canonização
	 */
	private void fourthStepToComputationDisgestValueWithDate(
			OutputStream octetStream, Time time)
			throws SignatureAttributeException, EncodingException {
		Node certificateValuesPropertiesNode = signatureElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						CERTIFICATE_VALUES).item(0);
		if (certificateValuesPropertiesNode == null) {
			throw new SignatureAttributeException(
					SignatureAttributeException.MISSING_CERTIFICATE_VALUES);
		}
		Node revocationValuesPropertiesNode = signatureElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						REVOCATION_VALUES).item(0);
		if (revocationValuesPropertiesNode == null) {
			throw new SignatureAttributeException(
					SignatureAttributeException.MISSING_REVOCATION_VALUES);
		}
		Node unsignedPropertiesNode = signatureElement.getElementsByTagNameNS(
				NamespacePrefixMapperImp.XADES_NS, UNSIGNED_PROPERTIES).item(0);
		if (unsignedPropertiesNode != null) {
			canonicalizeUnsignedSignatureProperties(octetStream, time);
		} else {
			throw new SignatureAttributeException(
					SignatureAttributeException.UNSIGNED_PROPERTIES_NOT_FOUND);
		}
	}

	/**
	 * Canoniza as propriedades não-assinadas da assinatura
	 * @param octetStream O octetstream em que o resultado será colocado
	 * @param time Horário do carimbo de tempo de arquivamento
	 * @throws EncodingException Exceção em caso de erro na canonização
	 * @throws SignatureAttributeException Exceção em caso de erro na manipulação dos atributos
	 * @throws TimeStampException Exceção em caso de erro no carimbo de tempo
	 */
	private void canonicalizeUnsignedSignatureProperties(
			OutputStream octetStream, Time time) throws EncodingException,
			SignatureAttributeException, TimeStampException {
		NodeList unsignedSignatureProperties = (NodeList) signatureElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						UNSIGNED_SIGNATURE_PROPERTIES).item(0);
		for (int i = 0; i < unsignedSignatureProperties.getLength(); i++) {
			Element nodeValue = (Element) unsignedSignatureProperties.item(i);
			if (nodeValue.getNodeName().equals(XADES_ARCHIVE_TIME_STAMP)) {
				ArchiveTimeStamp archiveTimeStamp = new ArchiveTimeStamp(
						(Element) nodeValue);
				if (archiveTimeStamp.getTimeReference().compareTo(time) < 0) {
					Canonicalizator.canonicalizationAndConcatenate(nodeValue,
							octetStream, this.canonicalizationMethodAlgorithm);
				}
			} else {
				Canonicalizator.canonicalizationAndConcatenate(nodeValue,
						octetStream, this.canonicalizationMethodAlgorithm);
			}
		}
	}

	/**
	 * Obtém todos os elementos ds:Object (exceto o que contém o elemento
	 * xades:QualifyingProperties), canoniza cada um deles e concatena seu
	 * hash no octet stream final.
	 * @param octetStream Os bytes para o cálculo do hash do carimbo de arquivamento
	 * @throws SignatureAttributeException Exceção em caso de erro na canonização
	 */
	private void fifthStepToComputationDisgestValue(OutputStream octetStream)
			throws SignatureAttributeException {
		NodeList unsignedSignatureProperties = (NodeList) signatureElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS,
						"Object").item(0);
		for (int i = 0; i < unsignedSignatureProperties.getLength(); i++) {
			Node nodeValue = unsignedSignatureProperties.item(i);
			if (!(nodeValue.getLocalName().equals(QUALIFYING_PROPERTIES))) {
				Canonicalizator.canonicalizationAndConcatenate(nodeValue,
						octetStream, this.canonicalizationMethodAlgorithm);
			}
		}
	}

	/**
	 * Retorna o contêiner da assinatura XAdES
	 * @return O contêiner da assinatura XAdES
	 */
	public XadesSignatureContainer getContainer() {
		return new XadesSignatureContainer(this.xml);
	}

	/**
	 * Calcula o hash das referências
	 * @param hashAlgorithmId O algoritmo utilizado no cálculo
	 * @param uris As URIs das referências a serem consideradas no cálculo
	 * @return O array de bytes do hash das referências
	 * @throws SignatureAttributeException Exceção em caso de nenhuma referência ser encontrada
	 */
	public byte[] getReferencesHashValue(String hashAlgorithmId,
			List<String> uris) throws SignatureAttributeException {
		List<Element> elementsToHash = new ArrayList<Element>();
		NodeList signedInfoNodeList = this.signatureElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS,
						SIGNED_INFO);
		Element signedInfo = (Element) signedInfoNodeList.item(0);
		NodeList referencesNodeList = signedInfo.getElementsByTagNameNS(
				NamespacePrefixMapperImp.XMLDSIG_NS, REFERENCE);
		for (int i = 0; i < referencesNodeList.getLength(); i++) {
			Element reference = (Element) referencesNodeList.item(i);

			String id = reference.getAttribute(ID);
			if (uris.contains(id)) {
				elementsToHash.add(reference);
			}
		}
		return getReferencesHash(hashAlgorithmId, elementsToHash);
	}

	/**
	 * Calcula o hash da lista de referências
	 * @param algorithm O algoritmo utilizado no cálculo
	 * @param elementsReference A lista de nodos de referências
	 * @return O array de bytes do hash das referências
	 * @throws SignatureAttributeException Exceção em caso de nenhuma referência ser encontrada
	 */
	private byte[] getReferencesHash(String algorithm,
			List<Element> elementsReference) throws SignatureAttributeException {
		ByteArrayOutputStream octetStream = null;
		if (elementsReference != null && !elementsReference.isEmpty()) {
			octetStream = new ByteArrayOutputStream();
			for (Element elementReference : elementsReference) {

				Canonicalizator.canonicalizationAndConcatenate(
						elementReference, octetStream);
			}
		} else
			throw new SignatureAttributeException(
					"É necessário ter pelo menos uma referência para obter o hash.");
		return Canonicalizator.getHash(algorithm, octetStream.toByteArray());
	}
	
	/**
	 * Retorna os certificados da estrutura KeyInfo
	 * @return Os certificados da estrutura KeyInfo ou nulo em caso de erro
	 */
	public List<X509Certificate> getCertificatesAtKeyInfo() {

		XMLSignatureFactory factory = XMLSignatureFactory.getInstance(DOM);
		XMLSignature sig = null;

		try {
			sig = factory.unmarshalXMLSignature(new DOMStructure(
					signatureElement));
		} catch (MarshalException e) {
			Application.logger.log(Level.SEVERE,
					"Problema na codificação da assinatura", e);
		}

		if (sig.getKeyInfo() != null) {
			return getCertificatesOfKeyInfo(sig);
		}
		
		return null;

	}

	/**
	 * Retorna as CRLs da assinatura
	 * @return As CRLs da assinatura
	 * @throws CRLException Exceção em caso de erro na manipulação das CRLs
	 */
    public List<X509CRL> getCrls() throws CRLException {
        
    	XMLSignatureFactory factory = XMLSignatureFactory.getInstance(DOM);
		XMLSignature sig = null;
		
		try {
			sig = factory.unmarshalXMLSignature(new DOMStructure(signatureElement));
		} catch (MarshalException e) {
			Application.logger.log(Level.SEVERE, "Problema na codificação da assinatura", e);
		}
		
		if (sig.getKeyInfo() != null) {
			return getCrlsOfKeyInfo(sig);
		}
		
		return null;
 
    }
    
	/**
	 * Retorna a lista de CRLs da estrutura KeyInfo
	 * @param sig A assinatura que contém o KeyInfo
	 * @return A lista de crls da estrutura KeyInfo
	 */
	private ArrayList<X509CRL> getCrlsOfKeyInfo(XMLSignature sig) {
		List<XMLStructure> keyInfoContent = sig.getKeyInfo().getContent();
		ArrayList<X509CRL> crls = new ArrayList<X509CRL>();
		if (!keyInfoContent.isEmpty()) {
			for (Object x509Data : keyInfoContent) {
				if(x509Data instanceof X509Data) {
	 				addX509DataContent(null, crls, (X509Data) x509Data);
				}
			}
		}
		return crls;
	}

	/**
	 * Retorna a lista de certificados da estrutura KeyInfo
	 * @param sig A assinatura que contém o KeyInfo
	 * @return A lista de certificados da estrutura KeyInfo
	 */
	private ArrayList<X509Certificate> getCertificatesOfKeyInfo(XMLSignature sig) {
		List<XMLStructure> keyInfoContent = sig.getKeyInfo().getContent();
		ArrayList<X509Certificate> certificates = new ArrayList<X509Certificate>();
		if (!keyInfoContent.isEmpty()) {
			for (Object x509Data : keyInfoContent) {
				if(x509Data instanceof X509Data) {
	 				addX509DataContent(certificates, null, (X509Data) x509Data);
				}
			}
		}
		return certificates;
	}

	/**
	 * Adiciona os certificados e CRLs, presentes na estrutura X509Data, nas listas dadas
	 * @param certificates A lista de certificados
	 * @param crls A lista de CRLs
	 * @param x509Data A estrutura X509Data
	 */
	public static void addX509DataContent(ArrayList<X509Certificate> certificates, List<X509CRL> crls, X509Data x509Data) {
		for (Object x509DataContent : x509Data.getContent()) {
			if (x509DataContent instanceof X509Certificate && certificates != null) {
				certificates.add((X509Certificate) x509DataContent);
			} else if (x509DataContent instanceof X509CRL && crls != null) {
				crls.add((X509CRL) x509DataContent);
			} else if (x509DataContent instanceof DOMStructure) {
				Node node = ((DOMStructure) x509DataContent).getNode();
				try {
					byte[] bytes = Base64.getDecoder().decode(node.getTextContent());
					CertificateFactory certificateFactory = CertificateFactory.getInstance("x509");

					if (node.getNodeName().equals("X509Certificate") && certificates != null) {
						Certificate cert = certificateFactory.generateCertificate(new ByteArrayInputStream(bytes));
						certificates.add((X509Certificate) cert);
					} else if (node.getNodeName().equals("X509CRL") && crls != null) {
						CRL crl = certificateFactory.generateCRL(new ByteArrayInputStream(bytes));
						crls.add((X509CRL) crl);
					}
				} catch (Exception e) {
					Application.logger.log(Level.WARNING, "Problema na codificação do conteúdo do KeyInfo", e);
				}
			}
		}
	}

}
