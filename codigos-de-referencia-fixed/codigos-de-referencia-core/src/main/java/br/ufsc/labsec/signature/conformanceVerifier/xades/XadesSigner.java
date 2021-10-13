package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.CertificateValidation;
import br.ufsc.labsec.signature.SignatureDataWrapper;
import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.SignaturePolicyInterface.AdESType;
import br.ufsc.labsec.signature.SystemTime;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignerException;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.CertificationPathException;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.ValidationDataService;
import br.ufsc.labsec.signature.exceptions.AIAException;
import br.ufsc.labsec.signature.signer.FileFormat;
import br.ufsc.labsec.signature.signer.SignerType;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.Signer;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignerRules.ExternalSignedData;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.DataObjectFormat;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SignaturePolicyIdentifier;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.signer.signatureSwitch.SwitchHelper;

/**
 * Esta classe cria uma assinatura CXdES em um documento.
 * Estende {@link AbstractXadesSigner} e implementa {@link Signer}.
 */
public class XadesSigner extends AbstractXadesSigner implements Signer {

	protected static final String EMBARCADA = "Embarcada";
	protected static final String DESTACADA = "Destacada";
	protected static final String ANEXADA = "Anexada";
	protected static final String INTDESTACADA = "Internamente destacada";

	/**
	 * Indica se a assinatura possui conteúdo assinado destacado
	 */
	protected boolean isDetached;
	/**
	 * URL que indica o conteúdo assinado em uma assinatura destacada
	 */
	private String detachedUrl;
	/**
	 * Suite da assinatura
	 */
	private String suite;

	/**
	 * Construtor
	 * @param xadesSignature Componente de assinatura XAdES
	 */
	public XadesSigner(XadesSignatureComponent xadesSignature) {
		super(xadesSignature);
		this.xadesSignatureComponent = xadesSignature;

		this.isXml = false;

	}

	/**
	 * Inicializa o gerador de contêiner de assinatura
	 * @param target  Endereço do arquivo a ser assinado
	 * @param policyOid OID da política de assinatura usada
	 */
	@Override
	public void selectTarget(String target, String policyOid) {
		this.contentFile = new File(target);
		this.xadesSignatureComponent.signaturePolicyInterface.setActualPolicy(policyOid, null,
				AdESType.XAdES);

		this.mandatedSignedAttributeList = this.xadesSignatureComponent.signaturePolicyInterface
				.getMandatedSignedAttributeList();
		this.mandatedUnsignedAttributeList = this.xadesSignatureComponent.signaturePolicyInterface
				.getMandatedUnsignedSignerAttributeList();

		if (FilenameUtils.getExtension(target).equals("xml")) {
			this.isXml = true;
		}

	}

	/**
	 * Inicializa o gerador de contêiner de assinatura
	 * @param target O arquivo que será assinado
	 * @param policyOid OID da política de assinatura utilizada
	 */
	@Override
	public void selectTarget(InputStream target, String policyOid) {
		return;
	}

	/**
	 * Inicializa o gerador de contêiner de assinatura
	 * @param target O arquivo que será assinado
	 * @param policyOid OID da política de assinatura utilizada
	 * @param filename Nome do arquivo de assinatura
	 */
	public void selectTarget(InputStream target, String policyOid, String filename) {
		this.isXml = true;
		File contentFile = null;
		try {
			contentFile = File.createTempFile(filename, ".xml");
			contentFile.deleteOnExit();
			FileOutputStream out = new FileOutputStream(contentFile);
			IOUtils.copy(target, out);
		} catch (IOException e) {
			Application.logger.log(Level.WARNING, "Não foi possível gerar o conteúdo a ser assinado a partir"
					+ "do InputStream de entrada", e);
		}
		this.contentFile = contentFile;
		this.xadesSignatureComponent.signaturePolicyInterface.setActualPolicy(
				policyOid, null, AdESType.XAdES);

		this.mandatedSignedAttributeList = this.xadesSignatureComponent.signaturePolicyInterface
				.getMandatedSignedAttributeList();
		this.mandatedUnsignedAttributeList = this.xadesSignatureComponent.signaturePolicyInterface
				.getMandatedUnsignedSignerAttributeList();
	}

	/**
	 * Inicializa o gerador de contêiner de assinatura
	 * @param target O arquivo que será assinado
	 * @param policyOid OID da política de assinatura utilizada
	 * @param url URL do arquivo assinado em uma assinatura destacada
	 */
	public void selectTarget(InputStream target, String policyOid, String filename, String url) {
		this.detachedUrl = url;
		this.selectTarget(target, policyOid, filename);
	}

	/**
	 * Atribue os valores de chave privada e certificado do assinante para a realização da assinatura
	 * @param keyStore {@link KeyStore} que contém as informações do assinante
	 * @param password Senha do {@link KeyStore}
	 */
	public void selectInformation(KeyStore keyStore, String password) throws KeyStoreException {
		String alias = SwitchHelper.getAlias(keyStore);
		PrivateKey privateKey = SwitchHelper.getPrivateKey(keyStore, alias, password.toCharArray());
		Certificate certificate = keyStore.getCertificate(alias);
		try {
			this.xadesSignatureComponent.privateInformation = new SignerData((X509Certificate) certificate, privateKey);
		} catch (SignerException e) {
			Application.logger.log(Level.WARNING, "Não foi possível atribuir os valores de"
					+ "chave privada e certificado do assinante", e);
		}
	}

	/**
	 * Realiza a assinatura
	 * @return Indica se o processo de assinatura foi concluído com sucesso
	 */
	@Override
	public boolean sign() {

		if (mode == null)
			return false;

		String[] policyHashAlgorithms =  this.xadesSignatureComponent.signaturePolicyInterface.getHashAlgorithmIdSet();
		String suiteAlgName = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(suite);
		String suiteAlgURL = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(suiteAlgName);
		boolean suiteInPolicy = false;
		for (int i = 0; i < policyHashAlgorithms.length && !suiteInPolicy; i++) {
			String hashAlgorithm = policyHashAlgorithms[i];
			suiteInPolicy = hashAlgorithm.equals(suiteAlgURL);
		}
		if (!suiteInPolicy) {
			return false;
		}

		// Removendo os obrigatórios
		selectedAttributes.remove(SignaturePolicyIdentifier.IDENTIFIER);

		List<String> unsignedOptionalAttributes = new ArrayList<>();

		PrivateKey privateKey = this.xadesSignatureComponent.privateInformation.getPrivateKey();
		X509Certificate signerCertificate = this.xadesSignatureComponent.privateInformation.getCertificate();

		SignatureContainerGenerator signatureContainerGenerator = null;
		SignerData signer = null;
		try {
			signer = new SignerData(signerCertificate, privateKey);

			if(this.mode == SignatureModeXAdES.INTERNALLYDETACHED) {
				Document toBeSigned = null;
				DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
				documentBuilderFactory.setNamespaceAware(true);
				DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
				try {
					toBeSigned = documentBuilder.parse(new FileInputStream(contentFile));
				} catch (IOException | SAXException e) {
					Application.logger.log(Level.SEVERE, e.getMessage(), e);
				}

				XPathFactory xPathFactory = XPathFactory.newInstance();
				XPath xpath = xPathFactory.newXPath();

				XPathExpression exprAssertion = xpath.compile("/*");
				Element assertionNode = (Element) exprAssertion.evaluate(toBeSigned, XPathConstants.NODE);

				String correctID = "id";
				NodeList nodeList = (NodeList) xpath.evaluate("/*/@*", toBeSigned, XPathConstants.NODESET);
				int length = nodeList.getLength();
				for( int i = 0; i < length; i++) {
					Attr attr = (Attr) nodeList.item(i);
					String name = attr.getName();
					if(name.toLowerCase().equals(correctID)) {
						correctID = name;
					}
				}

				XPathExpression exprAssertionID = xpath.compile("/*/@"+correctID+"");
				String assertionID = (String) exprAssertionID.evaluate(toBeSigned, XPathConstants.STRING);

				Document rootDocument = documentBuilder.newDocument();
				Element rootElement = rootDocument.createElement("internally-detached");
				Node importedNode = rootDocument.importNode(assertionNode, true);
				rootElement.appendChild(importedNode);
				rootDocument.appendChild(rootElement);

				DOMSource source = new DOMSource(rootDocument);
				File tempFile = File.createTempFile("internally-det-content-" + assertionID, ".xml");
				tempFile.deleteOnExit();
				FileWriter writer = new FileWriter(tempFile);
				StreamResult result = new StreamResult(writer);

				TransformerFactory transformerFactory = TransformerFactory.newInstance();
				Transformer transformer = transformerFactory.newTransformer();
				transformer.transform(source, result);

				this.contentToBeSigned = new FileToBeSigned(tempFile, mode, correctID, assertionID);
			} else if (mode == SignatureModeXAdES.DETACHED &&
					(this.detachedUrl != null && this.detachedUrl != "")){
				this.contentToBeSigned = new FileToBeSigned(detachedUrl, mode);
			} else {
				this.contentToBeSigned = new FileToBeSigned(contentFile, mode);
			}

			XadesContentToBeSigned contentAsXadesContent = (XadesContentToBeSigned) this.contentToBeSigned;
			if (mode == SignatureModeXAdES.ENVELOPED || this.mode == SignatureModeXAdES.INTERNALLYDETACHED) {
				Element element = contentAsXadesContent.getAsDocument().getDocumentElement();
				contentAsXadesContent.setEnvelopeNode(element);
			}

			SignaturePolicyIdentifier sigPolicyIdentifier = (SignaturePolicyIdentifier) attributeFactory
					.getAttribute(SignaturePolicyIdentifier.IDENTIFIER);
			signatureContainerGenerator = new SignatureContainerGenerator(sigPolicyIdentifier, xadesSignatureComponent);
		} catch (Exception e) {
			Application.logger.log(Level.SEVERE, e.getMessage(), e);
			return false;
		}

		if (!this.isDetached) {
			this.selectedAttributes.remove(DataObjectFormat.IDENTIFIER);
		}
		return doSign(unsignedOptionalAttributes, signatureContainerGenerator, signer);

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
			return saveSignature();
		} catch (EncodingException e) {
			Application.logger.log(Level.SEVERE, "Não foi possível salvar a assinatura", e);
		}
		return false;
	}

	/**
	 * Retorna a lista dos modos de assinatura disponíveis
	 * @return Lista dos modos de assinatura disponíveis
	 */
	@Override
	public List<String> getAvailableModes() {

		List<String> availableModes = new ArrayList<String>();

		ExternalSignedData availableMode = this.xadesSignatureComponent.signaturePolicyInterface
				.getExternalSignedData();
		if (availableMode.name().equals(ExternalSignedData.EXTERNAL.name())) {
			availableModes.add(DESTACADA);
		}
		if ((availableMode.name().equals(ExternalSignedData.INTERNAL.name())) && isXml) {
			availableModes.add(EMBARCADA);
			availableModes.add(ANEXADA);
		}
		if (availableMode.name().equals(ExternalSignedData.EITHER.name())) {
			availableModes.add(DESTACADA);
			availableModes.add(ANEXADA);
			if (isXml) {
				availableModes.add(EMBARCADA);
			}
		}

		return availableModes;
	}

	/**
	 * Atribue o modo de assinatura
	 * @param mode O modo da assinatura
	 */
	@Override
	public void setMode(FileFormat mode, String suite) {
		this.isDetached = false;
		if (mode.equals(FileFormat.ATTACHED)) {
			this.mode = SignatureModeXAdES.ENVELOPING;
		} else if (mode.equals(FileFormat.DETACHED)) {
			this.mode = SignatureModeXAdES.DETACHED;
			this.isDetached = true;
		} else if (mode.equals(FileFormat.ENVELOPED)) {
			this.mode = SignatureModeXAdES.ENVELOPED;
		} else if (mode.equals(FileFormat.INTERNALLY_DETACHED)) {
			this.mode = SignatureModeXAdES.INTERNALLYDETACHED;
		}
		this.suite = suite;
	}

	@Override
	public boolean supports(InputStream target, SignerType signerType) throws CertificationPathException, SignerException {
		Certificate certificate = this.xadesSignatureComponent.privateInformation.getCertificate();
		SignaturePolicyInterface signaturePolicyInterface = this.xadesSignatureComponent.signaturePolicyInterface;
		CertificateValidation certificateValidation = this.xadesSignatureComponent.certificateValidation;
		Set<TrustAnchor> trustAnchors = signaturePolicyInterface.getSigningTrustAnchors();

		if (certificate != null) {
			try {
				List<X509Certificate> certificates = ValidationDataService.downloadCertChainFromAia((X509Certificate) certificate);
				this.getComponent().getSignatureIdentityInformation().addCertificates(certificates);
			} catch (AIAException | NullPointerException e) {
				Application.logger.log(Level.SEVERE, "Erro ao obter o AIA no supports");
			}
		}

		CertPath certPath = certificateValidation.generateCertPath(certificate, trustAnchors, new Time(SystemTime.getSystemTime()));
		if (certPath == null) {
			throw new CertificationPathException(CertificationPathException.NULL_CERT_PATH);
		}
		return true;
	}

	/**
	 * Realiza a assinatura
	 * @param signatureContainerGenerator Gerador de contêineres de assinaturas XAdES
	 * @return Indica se o processo de assinatura foi concluído com sucesso
	 */
	@Override
	protected Signature sign(SignatureContainerGenerator signatureContainerGenerator) {
		try {
			this.signatureContainer = signatureContainerGenerator.sign();
			return this.signatureContainer.getSignatureAt(0);
		} catch (PbadException e) {
			Application.logger.log(Level.SEVERE, e.getMessage(), e);
		}
		return null;
	}

	/**
	 * Retorna a lista de atributos da assinatura
	 * @return A lista de atributos da assinatura
	 */
	@Override
	public List<String> getAttributesAvailable() {
		// TODO Auto-generated method stub
		return null;
	}

	public SignatureDataWrapper getSignature(String filename, InputStream target, SignerType policyOid, String url) {
		selectTarget(target, policyOid.toString(), filename, url);
		if (sign()) {
			InputStream stream = getSignatureStream();
			SignatureDataWrapper signature = new SignatureDataWrapper(stream, null, filename);
			return signature;
		}
		return null;
	}

}
