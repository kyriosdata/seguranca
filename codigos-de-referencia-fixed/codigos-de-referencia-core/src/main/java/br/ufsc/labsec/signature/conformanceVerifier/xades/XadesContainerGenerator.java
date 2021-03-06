package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.sql.Time;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import br.ufsc.labsec.signature.SystemTime;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import br.ufsc.labsec.signature.ContentToBeSigned;
import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignerRules.CertInfoReq;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.DataObjectFormat;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.AlgorithmException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureModeException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.ToBeSignedException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.XadesSignatureException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.XmlProcessingException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe ?? utilizada apenas pela classe
 * {@link SignatureContainerGenerator}. N??o deve ser utilizada pelo usu??rio.
 * Implementa {@link ContainerGenerator}.
 */
public class XadesContainerGenerator implements ContainerGenerator {

	/**
	 * A URI base do arquivo
	 */
	private URI baseUri;
	/**
	 * Documento a ser assinado
	 */
	private Document documentToSign;
	/**
	 * Nodo que conter?? a assinatura
	 */
	private Element nodeToEnvelope;
	/**
	 * Mapa entre os conte??dos a serem assinados e seu ID
	 */
	private Map<XadesContentToBeSigned, String> contentsIdMap;
	/**
	 * Mapa entre DataObjectFormat e seu ID
	 */
	private Map<XadesContentToBeSigned, String> dataObjectFormatIdMap;
	/**
	 * Lista de atributos da assinatura
	 */
	private List<SignatureAttribute> attributeList;
	/**
	 * Lista de conte??dos a serem assinados
	 */
	private List<XadesContentToBeSigned> contentToBeSignedList;
	/**
	 * Identificador da assinatura
	 */
	private String signatureId;
	/**
	 * F??brica de assinaturas XML
	 */
	private XMLSignatureFactory factory;
	/**
	 * Mapa entre refer??ncias e seus IDs
	 */
	private Map<Reference, String> referenceMap;
	/**
	 * Identificador de atributo assinado
	 */
	private String signedAttributeId;
	/**
	 * Pol??tica de assinatura
	 */
	private SignaturePolicyInterface signaturePolicy;
	/**
	 * Informa????es do assinante
	 */
	private SignerData signer;
	private static String[] SIGNEDSIGNATURE_IDENTIFIERS_ORDER = { "SigningTime", "SigningCertificate",
			"SignaturePolicyIdentifier", "SignatureProductionPlace", "SignerRole" };
	private static String[] SIGNEDDATAOBJECT_IDENTIFIERS_ORDER = { "DataObjectFormat", "CommitmentTypeIndication",
			"AllDataObjectsTimeStamp", "IndividualDataObjectsTimeStamp" };
	/**
	 * Componente de assinatura XAdES
	 */
	private XadesSignatureComponent component;

	/**
	 * Constr??i um {@link XadesContainerGenerator} a partir da Pol??tica de
	 * Assinatura usada na assinatura
	 * 
	 * @param signaturePolicy A pol??tica de assinatura
	 * @param component Componente de assinatura XAdES
	 */
	public XadesContainerGenerator(SignaturePolicyInterface signaturePolicy, XadesSignatureComponent component) {
		java.lang.System.setProperty("org.jcertPath.xml.dsig.secureValidation", "false"); 
		this.contentToBeSignedList = new ArrayList<XadesContentToBeSigned>();
		this.contentsIdMap = new HashMap<XadesContentToBeSigned, String>();
		this.dataObjectFormatIdMap = new HashMap<XadesContentToBeSigned, String>();
		this.referenceMap = new HashMap<Reference, String>();
		this.signaturePolicy = signaturePolicy;
		this.component = component;
	}

	/**
	 * Atribue os conte??dos a serem assinados
	 * @param contentsToBeSigned A lista de conte??dos a serem assinados
	 * @throws SignatureModeException Exce????o em caso de modo de assinatura inv??lido
	 * @throws ToBeSignedException Exce????o em caso de erro na URI do conte??do a ser assinado
	 */
	public void setContentsToBeSigned(List<ContentToBeSigned> contentsToBeSigned) throws SignatureModeException, ToBeSignedException {
		for (ContentToBeSigned content : contentsToBeSigned) {
			XadesContentToBeSigned xadesContent = (XadesContentToBeSigned) content;
			this.contentToBeSignedList.add(xadesContent);
			URI otherBaseUri = xadesContent.getBaseUri();
			if (otherBaseUri != null && baseUri == null)
				this.baseUri = otherBaseUri;
			if (xadesContent.modeNeedSpecificDocument()) {
				if (this.documentToSign == null) {
					this.documentToSign = xadesContent.getAsDocument();
					this.nodeToEnvelope = xadesContent.getEnvelopNode();
					String newBaseUri = this.documentToSign.getBaseURI();
					if (newBaseUri == null)
						newBaseUri = "";
					try {
						this.baseUri = new URI(newBaseUri);
					} catch (URISyntaxException uriSyntaxException) {
						throw new ToBeSignedException(uriSyntaxException);
					}
				} else {
					throw new SignatureModeException(
							"Voc?? s?? pode adicionar um conte??do para assinar no modo Enveloped.");
				}
			}
			this.contentsIdMap.put(xadesContent, generateNewId());
		}
	}

	/**
	 * Substitui a lista de atributos e atualiza a lista de DataObjectFormat
	 * @param attributes A lista de atributos
	 */
	public void setAttributes(List<SignatureAttribute> attributes) {
		this.attributeList = attributes;
		for (SignatureAttribute attribute : attributes) {
			if (attribute.getIdentifier().equals("DataObjectFormat")) {
				DataObjectFormat dataObjectFormat = (DataObjectFormat) attribute;
				this.dataObjectFormatIdMap.put(dataObjectFormat.getContent(), dataObjectFormat.getObjectReference());
			}
		}
	}

	/**
	 * Gera o cont??iner da assinatura XAdES
	 * @return O cont??iner gerado
	 * @throws PbadException Exce????o em caso de erro na cria????o do cont??iner
	 * @throws AlgorithmException
	 */
	@Override
	public SignatureContainer generate() throws PbadException, AlgorithmException {
		if (this.documentToSign == null) {
			try {
				this.documentToSign = getNewDocument();
				if (this.baseUri != null)
					this.documentToSign.setDocumentURI(this.baseUri.toString());
			} catch (ParserConfigurationException e) {
				throw new PbadException(e);
			}
		}
		XadesSignatureContainer xadesSignatureContainer = null;
		XMLSignature signature;
		try {
			signature = getXmlSignature();	
			DOMSignContext signatureContext = getSignatureContext();
			signature.sign(signatureContext);
			xadesSignatureContainer = new XadesSignatureContainer(this.documentToSign);
			// xadesSignatureContainer = new
			// XadesSignatureContainer(signatureContext.getParent().getOwnerDocument());
		} catch (XMLSignatureException e) {
			throw new XadesSignatureException(e);
		} catch (XmlProcessingException e) {
			throw new XadesSignatureException(e);
		} catch (MarshalException e) {
			throw new XadesSignatureException(e);
		}
		return xadesSignatureContainer;
	}

	/**
	 * Atribue o valor dos dados do assinante
	 * @param signer Os dados do assinante
	 */
	@Override
	public void setSigner(SignerData signer) {
		this.signer = signer;
	}

	/**
	 * Instancia um novo {@link Document}, que ser?? usado para escrever a
	 * assinatura.
	 * @return O objeto gerado
	 * @throws ParserConfigurationException Exce????o em caso de erro na gera????o do documento
	 */
	protected Document getNewDocument() throws ParserConfigurationException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		return factory.newDocumentBuilder().newDocument();
	}

	/**
	 * Instancia um novo contexto de assinatura({@link DOMSignContext}), que ??
	 * necess??rio para indicar, por exemplo, onde est?? o documento que vai ser
	 * assinado
	 * @return O contexto de assinatura criado
	 */
	protected DOMSignContext getSignatureContext() {
		DOMSignContext context = null;
		if (this.nodeToEnvelope != null) {
			context = new DOMSignContext(this.signer.getPrivateKey(), this.nodeToEnvelope);
		} else {
			context = new DOMSignContext(this.signer.getPrivateKey(), this.documentToSign);
		}
		context.setDefaultNamespacePrefix("ds");
		if (this.baseUri != null)
			context.setBaseURI(this.baseUri.toString());
		return context;
	}

	/**
	 * Instancia uma nova {@link XMLSignature} que ?? capaz de assinar documentos
	 * conforme o que est?? previsto na pol??tica de assinaturas AD-RB
	 * @return Uma nova assinatura XML
	 * @throws EncodingException
	 * @throws SignatureAttributeException  Exce????o em caso de erro na busca dos atributos da assinatura
	 * @throws AlgorithmException Exce????o caso o algoritmo de assinatura da PA seja inv??lido
	 * @throws XmlProcessingException Exce????o em caso de erro na manipula????o da estrutura XML
	 * @throws SignatureModeException Exce????o em caso de modo de assinatura inv??lido
	 * @throws ToBeSignedException Exce????o em caso de erro na manipula????o dos dados a serem assinados
	 * @throws XadesSignatureException Exce????o em caso de erro na manipula????o da assinatura XAdES
	 */
	protected XMLSignature getXmlSignature() throws SignatureAttributeException, EncodingException, AlgorithmException,
			XmlProcessingException, SignatureModeException, ToBeSignedException, XadesSignatureException {
		List<XMLObject> xmlListObjects = new ArrayList<XMLObject>();
		xmlListObjects.add(getQualifyingPropertiesObject());
		for (XadesContentToBeSigned content : this.contentToBeSignedList) {
			XMLObject object = content.getObject(this.contentsIdMap.get(content));
			if (object != null)
				xmlListObjects.add(object);
		}
		SignedInfo signedInfo = getSignedInfo();
		KeyInfo keyInfo = getKeyInfo();
		XMLSignature signature = getFactory().newXMLSignature(signedInfo, keyInfo, xmlListObjects, getSignatureId(),
				generateNewId());
		return signature;
	}

	/**
	 * Gera um objeto {@link KeyInfo} de acordo com as informa????es do assinante
	 * @return O {@link KeyInfo} criado
	 */
	private KeyInfo getKeyInfo() {
				
		CertInfoReq certInfoReq = this.signaturePolicy.getMandatedCertificateInfo();
						
		KeyInfoFactory keyInfoFactory = getFactory().getKeyInfoFactory();
		KeyInfo keyInfo = null;
		X509Data data = null;
		
		switch (certInfoReq) {
		case NONE:
				break;	
			
		case SIGNER_ONLY:
			
			data = keyInfoFactory.newX509Data(Collections.singletonList(this.signer.getCertificate()));
			keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(data));

			break;
			
		case FULL_PATH:
			
			CertPath certPath = this.component.certificateValidation.generateCertPath(this.signer.getCertificate(), this.signaturePolicy.getSigningTrustAnchors(), new Time(SystemTime.getSystemTime()));
						
			data = keyInfoFactory.newX509Data(certPath.getCertificates());
			keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(data)); 
			
			break;			
		}
		
		return keyInfo;

	}

	/**
	 * Essa ?? uma propriedade do elemento {@link XMLSignature}, que cont??m a
	 * informa????o dos arquivos assinados, assim como o resumo criptogr??fico e
	 * outras coisas
	 * @return Informa????es do arquivo assinado
	 * @throws AlgorithmException Exce????o caso o algoritmo de assinatura da PA seja inv??lido
	 * @throws SignatureModeException Exce????o em caso de modo de assinatura inv??lido
	 * @throws ToBeSignedException Exce????o em caso de erro na manipula????o dos dados a serem assinados
	 */
	protected SignedInfo getSignedInfo() throws AlgorithmException, SignatureModeException, ToBeSignedException {
		C14NMethodParameterSpec methodParameterSpec = null;
		CanonicalizationMethod canonicalizationMethod = null;
		SignatureMethod signatureMethod = null;
		DigestMethod digestMethod = null;
		try {
			canonicalizationMethod = getFactory().newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
					methodParameterSpec);
			signatureMethod = getFactory().newSignatureMethod(this.signaturePolicy.getSignatureAlgorithmIdentifier(),
					null);
			digestMethod = getFactory().newDigestMethod(this.signaturePolicy.getHashAlgorithmId(), null);
		} catch (NoSuchAlgorithmException e) {
			throw new AlgorithmException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new AlgorithmException(e);
		}
		List<Reference> references = new ArrayList<Reference>();
		for (XadesContentToBeSigned content : this.contentToBeSignedList) {
			String newId = null;
			if (this.dataObjectFormatIdMap.get(content) != null) { 
				newId = this.dataObjectFormatIdMap.get(content); 
			} else { 
//				newId = this.contentsIdMap.get(content);
				newId = this.generateNewId();
			}
			Reference reference = content.getReference(newId, digestMethod, this.baseUri);
			this.referenceMap.put(reference, newId);
			references.add(reference);
		}
		// O tipo dessa refer??ncia ?? mencionada no documento TS 101 903 - V1.3.2
		// - ETSI.
		references.add(getFactory().newReference("#" + getSignedAttributeId(), digestMethod, null,
				"http://uri.etsi.org/01903#SignedProperties", null));
		// Obt??m o signedInfo.
		
		SignedInfo signedInfo = getFactory().newSignedInfo(canonicalizationMethod, signatureMethod, references);
		return signedInfo;
	}

	/**
	 * Tranforma o tipo {@link Document}, que representa a estrutura
	 * "QualyfiyingProperties" da assinatura que ser?? gerada, em um
	 * {@link XMLObject} para ser usado na API xml.cripto.dsig.
	 * 
	 * @return O {@link XMLObject} gerado
	 * @throws SignatureAttributeException Exce????o em caso de erro na busca dos atributos da assinatura
	 * @throws EncodingException
	 * @throws XmlProcessingException Exce????o em caso de erro na manipula????o da estrutura XML
	 * @throws XadesSignatureException Exce????o em caso de erro na manipula????o da assinatura XAdES
	 */
	protected XMLObject getQualifyingPropertiesObject() throws SignatureAttributeException, EncodingException,
			XmlProcessingException, XadesSignatureException {
		Element qualifyingPropertiesElement = getQualifyingProperties();
		
		//qualifyingPropertiesElement = (Element) this.documentToSign.importNode(qualifyingPropertiesElement, true);
		
		NodeList nodes = qualifyingPropertiesElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "SignedProperties");
		Element element = (Element) nodes.item(0);
		element.setIdAttribute("Id", true);
		
		XMLStructure qualifyingPropertiesStructure = new DOMStructure(qualifyingPropertiesElement);
		List<XMLStructure> contentList = new ArrayList<XMLStructure>();
		contentList.add(qualifyingPropertiesStructure);
		XMLObject xmlObject = getFactory().newXMLObject(contentList, null, null, null);
		return xmlObject;
	}

	/**
	 * Retorna os nodos da estrutura 'QualyfiyingProperties' da assinatura
	 * @return Uma ??rvore XML com os nodos da estrutura 'QualyfiyingProperties' da assinatura
	 * @throws EncodingException
	 * @throws XadesSignatureException Exce????o em caso de erro na manipula????o da assinatura XAdES
	 * @throws SignatureAttributeException Exce????o em caso de erro na busca dos atributos da assinatura
	 */
	private Element getQualifyingProperties() throws EncodingException, XadesSignatureException,
			SignatureAttributeException {
		
		Element qualifyingPropertiesDocument = this.documentToSign.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:QualifyingProperties");
		qualifyingPropertiesDocument.setAttribute("xmlns:XAdES", NamespacePrefixMapperImp.XADES_NS);
		
		Element signedProperties = this.documentToSign.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:SignedProperties");
		qualifyingPropertiesDocument.appendChild(signedProperties);
		
		signedProperties.setAttribute("Id", this.getSignedAttributeId());
		
		Element signedSignatureProperties = this.documentToSign.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:SignedSignatureProperties");
		signedProperties.appendChild(signedSignatureProperties);
		
		
		qualifyingPropertiesDocument.setAttribute("Target", "#" + this.getSignatureId());
		
		for (int i = 0; i < XadesContainerGenerator.SIGNEDSIGNATURE_IDENTIFIERS_ORDER.length; i++) {
			boolean found = false;
			int j = 0;
			while (!found && j < this.attributeList.size()) {
				if (XadesContainerGenerator.SIGNEDSIGNATURE_IDENTIFIERS_ORDER[i].equals(this.attributeList.get(j)
						.getIdentifier())) {
					Node attributeNode = this.attributeList.get(j).getEncoded();
					signedSignatureProperties.appendChild(this.documentToSign.importNode(attributeNode, true));
					found = true;
				}
				j++;
			}
		}
		Element signedPropertiesElement = (Element) qualifyingPropertiesDocument.getElementsByTagNameNS(
				NamespacePrefixMapperImp.XADES_NS, "SignedProperties").item(0);
		Element signedDataObjectProperties = null;
		for (int i = 0; i < XadesContainerGenerator.SIGNEDDATAOBJECT_IDENTIFIERS_ORDER.length; i++) {
			for (SignatureAttribute attribute : this.attributeList) {
				if (signedDataObjectProperties == null
						&& signedPropertiesElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
								"SignedDataObjectProperties").getLength() == 0) {
					signedDataObjectProperties = this.documentToSign.createElementNS(
							NamespacePrefixMapperImp.XADES_NS, "XAdES:SignedDataObjectProperties");
					signedPropertiesElement.appendChild(signedDataObjectProperties);
				}
				if (XadesContainerGenerator.SIGNEDDATAOBJECT_IDENTIFIERS_ORDER[i].equals(attribute.getIdentifier())) {
					Node attr = attribute.getEncoded();
					signedDataObjectProperties.appendChild(this.documentToSign.importNode(attr, true));
				}
			}
		}
		return qualifyingPropertiesDocument;
	}

	/**
	 * Gera um n??mero aleat??rio para ser usado como ID. O alcance dessa
	 * aleatoriedade precisa ser grande para assegurar a n??o repeti????o do ID
	 * dentro da assinatura.
	 * @return O identificador gerado
	 */
	protected String generateNewId() {
		long idNumber = (long) (Math.random() * 1000000 * 1000000 * 1000000) + 1;
		return "id" + idNumber;
	}

	/**
	 * Retorna o identificador da assinatura
	 * @return O identificador da assinatura
	 */
	protected String getSignatureId() {
		if (this.signatureId == null) {
			this.signatureId = this.generateNewId();
		}
		return this.signatureId;
	}

	/**
	 * Retorna um {@link XMLSignatureFactory} que ser?? usado na cria????o e
	 * montagem da assinatura.
	 * @return A inst??ncia do {@link XMLSignatureFactory}
	 */
	protected XMLSignatureFactory getFactory() {
		if (this.factory == null)
			this.factory = XMLSignatureFactory.getInstance("DOM");
		return this.factory;
	}

	/**
	 * Retorna o identificados de atributo assinado
	 * @return O identificador de atributo
	 */
	protected String getSignedAttributeId() {
		if (this.signedAttributeId == null) {
			this.signedAttributeId = this.generateNewId();
		}
		return this.signedAttributeId;
	}

}
