package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;

import javax.activation.FileTypeMap;
import javax.activation.MimetypesFileTypeMap;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.DataObjectFormat;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureModeException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.ToBeSignedException;


/**
 * Esta classe representa um arquivo que será assinado.
 * Estende {@link XadesContentToBeSigned}.
 */
public class FileToBeSigned extends XadesContentToBeSigned {

	/**
	 * O arquivo que será assinado
	 */
	private File file;
	/**
	 * Identificador do objeto XML a ser assinado
	 */
	private String id;
	/**
	 * Identificador da referência
	 */
	private String referenceId;
	/**
	 * Indica se a referência criada para o arquivo é absoluta
	 */
	private boolean absolute;

	/**
	 * URL que indica o conteúdo assinado em uma assinatura destacada
	 */
	private String detachedUrl;

	/**
	 * Essa classe representa um arquivo que será assinado. O arquivo pode ser
	 * assinado nos trê seguintes modos: <b>DETACHED</b>, <b>ENVELOPING</b> e
	 * <b>ENVELOPED</b>. O modo <b>DETACHED</b> precisa que você informe o
	 * {@link DataObjectFormat} correspondente a esse arquivo, para que mais
	 * tarde ele seja anexado também. E o modo <b>ENVELOPED</b> só pode ser
	 * usado para assinar arquivos XML, e ele também precisa que você informe em
	 * qual nodo a assinatura deve ser anexada, isso pode ser feito através do
	 * método {@link XadesContentToBeSigned}<b>.getAsDocument()</b>.
	 * 
	 * @param file O arquivo {@link File} que será assinado
	 * @param mode O modo de assinatura
	 * @throws SignatureModeException exceção caso o conteúdo <b>ENVELOPED</b> não seja XML
	 * @throws ToBeSignedException exceção caso o modo de assinar é <b>COUNTERSIGNED</b>.
	 */
	public FileToBeSigned(File file, SignatureModeXAdES mode) throws SignatureModeException, ToBeSignedException {
		super(mode);
		this.file = file;
		this.id = null;
		if (mode == SignatureModeXAdES.ENVELOPED) {
			/*
			 * Essa classe faz a verificação de tipos MIME pela extensão, pode
			 * não ser o mais apropriado, mas é uma boa solução para
			 * independência do sistema operacional
			 */
			MimetypesFileTypeMap fMap = new MimetypesFileTypeMap();
			fMap.addMimeTypes("application/xml xml XML xsd XSD");
			if (fMap.getContentType(file).compareTo("application/xml") != 0) {
				throw new SignatureModeException(
						"Para assinar um conteúdo na forma ENVELOPED, ele deve ser um XML, o conteúdo passado é: "
								+ fMap.getContentType(file));
			}
			this.setDocument(getDocumentToSign());
		}
		if (mode == SignatureModeXAdES.COUNTERSIGNED) {
			throw new SignatureModeException(
					"Use a classe XadesSignatureToBeSigned para contra assinar com formato XAdES.");
		}
	}

	public FileToBeSigned(File file, SignatureModeXAdES mode, String correctAttributeId, String idValue)
			throws ToBeSignedException {
		super(mode);
		this.file = file;
		this.id = idValue;
		if (mode == SignatureModeXAdES.INTERNALLYDETACHED) {
			this.setDocument(getDocumentToSign());
		}

		// Identifica que o atributo 'correctAttributeId'
		// é um atributo identificador. É necessário para
		// a validação das referências na assinatura
		XPathFactory xPathFactory = XPathFactory.newInstance();
		XPath xpath = xPathFactory.newXPath();
		try {
			XPathExpression exprAssertion = xpath.compile("/*/*");
			Element assertionNode = (Element) exprAssertion.evaluate(this.document, XPathConstants.NODE);
			assertionNode.setIdAttribute(correctAttributeId, true);
		} catch (XPathExpressionException e) {
			throw new ToBeSignedException("Erro na busca pelo atributo identificador no arquivo XML", e);
		}
	}

	public FileToBeSigned(String url, SignatureModeXAdES mode) {
		super(mode);
		this.absolute = true;
		this.detachedUrl = url;
	}

	/**
	 * Quando ainda não se tem uma {@link URI} base, pode-se pegar uma de algum
	 * arquivo que será assinado
	 * @return a URI base
	 */
	@Override
	URI getBaseUri() {
		URI result = null;
		if (this.getMode() == SignatureModeXAdES.DETACHED)
			if (this.file == null) {
				try {
					result = new URI(this.detachedUrl);
				} catch (URISyntaxException e) {
					Application.logger.log(Level.WARNING, "Não foi possível gerar a URI base através"
							+ "da URL do arquivo destacado.", e);
				}
			} else {
				result = (new File(this.file.getParent())).toURI();
			}
		return result;
	}

	/**
	 * Retorna o objeto XML correspondente ao identificador dado
	 * @param id O identificador do objeto XML
	 * @return O objeto XML correspondente ao identificador
	 * @throws ToBeSignedException Exceção em caso de erro na leitura do arquivo
	 */
	@Override
	public XMLObject getObject(String id) throws ToBeSignedException {
		XMLObject object = null;
		if (this.getMode() == SignatureModeXAdES.ENVELOPING) {
			this.id = id;
			FileTypeMap fileMap = FileTypeMap.getDefaultFileTypeMap();
			String mimeType = fileMap.getContentType(this.file);
			Document docMaker = this.getNewDocument();
			XMLSignatureFactory factory = XMLSignatureFactory.getInstance();
			List<XMLStructure> content = new LinkedList<XMLStructure>();
			byte[] bytes = null;
			try {
				InputStream stream = new FileInputStream(this.file);
				bytes = new byte[stream.available()];
				stream.read(bytes);
			} catch (IOException e) {
				throw new ToBeSignedException(e);
			}
			String data = new String(Base64.encode(bytes));
			Text node = docMaker.createTextNode(data);
			XMLStructure structure = new DOMStructure(node);
			content.add(structure);
			object = factory.newXMLObject(content, this.id, mimeType, "http://www.w3.org/2000/09/xmldsig#base64");
		}
		return object;
	}

	/**
	 * Retorna a URI de acordo com o tipo de assinatura
	 * @param baseUri URI absoluta de onde o arquivo de assinatura deve estar
	 *            para tipos de assinatura detached
	 * @return A URI criada de acordo com o tipo de assinatura
	 */
	@Override
	protected String getUri(URI baseUri) {
		String resultingUri = null;
		switch (this.getMode()) {
		case DETACHED:
			String resulting = null;
			if (this.absolute) {
				resulting = this.detachedUrl;
			} else {
				String base = baseUri.toString();
				resulting = this.file.toURI().toString();
				if (base.length() < resulting.length()) {
					resulting = resulting.substring(base.length());
				} else {
					if (!(new File(baseUri)).isDirectory()) {
						base = base.substring(0, base.lastIndexOf('/'));
					} else {
						base = base.substring(resulting.length());
					}
					char[] prefix = null;
					int length = 0;
					if (resulting.length() > base.length()) {
						prefix = new char[resulting.length()];
						length = base.length();
					} else {
						prefix = new char[base.length()];
						length = resulting.length();
					}
					int i = 0;
					while (i < length && base.charAt(i) == resulting.charAt(i)) {
						prefix[i] = base.charAt(i);
						i++;
					}
					String prefixStr = new String(prefix);
					base = base.substring(prefixStr.trim().length());
					resulting = resulting.substring(prefixStr.trim().length());
					if (base.length() > 0) {
						String[] baseDirectories = base.split(File.separator);

						for (i = 0; i < baseDirectories.length; i++) {
							resulting = "..".concat(File.separator).concat(resulting);
						}
					}
				}
			}
			return resulting;
		case COUNTERSIGNED:
		case ENVELOPING:
			resultingUri = "#" + this.id;
			break;
		case ENVELOPED:
			resultingUri = "";
			break;
		default:
			resultingUri = "#" + this.id;

		}
		return resultingUri;
	}

	/**
	 * Quando o modo de assinar o conteúdo é <b>ENVELOPED</b> o arquivo precisa
	 * ser instânciado em forma de {@link Document}.
	 * @return o arquivo a ser assinado como um objeto {@link Document}
	 * @throws ToBeSignedException exceção em caso de erro na leitura do arquivo
	 */
	private Document getDocumentToSign() throws ToBeSignedException {
		Document document = null;
		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true);
			DocumentBuilder builder = factory.newDocumentBuilder();
			document = builder.parse(this.file);
		} catch (Exception e) {
			throw new ToBeSignedException(e);
		}
		this.document = document;
		return document;
	}

	/**
	 * Retorna o identificador da referência da assinatura
	 * @return O identificador da referência
	 */
	@Override
	public String getReferenceId() {
		return this.referenceId;
	}

	/**
	 * Retorna o objeto de referência correspondente ao identificador
	 * @param id O id da refêrencia. É útil por exemplo quando se adiciona um
	 *            {@link DataObjectFormat} na assinatura
	 * @param digestMethod Identificador do algoritimo que será usado para o
	 *            respectivo conteúdo
	 * @param baseUri URI base para relativizar. É útil quando se tem mais de
	 *            um arquivo detached em pastas diferentes
	 * @return A referência correspondente
	 * @throws SignatureModeException Exceção caso o modo de assinatura seja inválido
	 * @throws ToBeSignedException Exceção em caso de erro na leitura do arquivo
	 */
	@Override
	public Reference getReference(String id, DigestMethod digestMethod, URI baseUri) throws SignatureModeException,
			ToBeSignedException {
		XMLSignatureFactory factory = XMLSignatureFactory.getInstance();
		if (this.getMode() == SignatureModeXAdES.ENVELOPING) {
			return factory.newReference(getUri(baseUri), digestMethod);
		}
		if (this.getMode() == SignatureModeXAdES.DETACHED) {
			if (this.detachedUrl != null && this.detachedUrl != "") {
				/* Referências não estão sendo geradas corretamente com link HTTPS,
				* então garantimos que a URL sempre utilizará HTTP */
				if(this.detachedUrl.startsWith("https")) {
					this.detachedUrl = this.detachedUrl.replaceFirst("^https", "http");
				}
				return factory.newReference (this.detachedUrl, digestMethod);
			}
			return factory.newReference(getUri(baseUri), digestMethod,
					this.getMode().getTransforms(this.getOperations()), this.getMode().getType(), id,
					this.getFileDigest(digestMethod));
		}
		// ENVELOPED and INTERNALLYDETACHED
		return factory.newReference(getUri(baseUri), digestMethod,
				this.getMode().getTransforms(this.getOperations()), this.getMode().getType(), id);
	}

	/**
	 * Retorna o resumo criptográfico do arquivo a ser assinado
	 * @param digestMethod o algoritmo de resumo
	 * @return O resumo criptográfico do arquivo
	 * @throws ToBeSignedException exceção em caso de parâmetros inválidos ou erro durante
	 * a realização do resumo
	 */
	private byte[] getFileDigest(DigestMethod digestMethod) throws ToBeSignedException {
		InputStream is;
		MessageDigest digester = null;
		byte[] fileBytes = new byte[0];
		try {
			is = new FileInputStream(this.file);
		} catch (FileNotFoundException fileNotFoundException) {
			throw new ToBeSignedException("Arquivo não encontrado", fileNotFoundException);
		}
		try {
			digester = MessageDigest.getInstance(AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(digestMethod
					.getAlgorithm()));
		} catch (NoSuchAlgorithmException noSuchAlgorithmException) {
			throw new ToBeSignedException("Algoritmo desconhecido", noSuchAlgorithmException);
		}
		try {
			fileBytes = IOUtils.toByteArray(is);
		} catch (IOException e) {
			throw new ToBeSignedException("Erro ao ler o arquivo", e);
		}
		return digester.digest(fileBytes);
	}

	/**
	 * Informa se a referência criada para o arquivo que esse conteúdo representa
	 * deve ser absoluta ou não
	 * @param absolute Indica se a referência criada para o arquivo deve ser absoluta
	 */
	public void setAbsolute(boolean absolute) {
		this.absolute = absolute;
	}

	/**
	 * Retorna o arquivo a ser assinado
	 * @return O arquivo {@link File} que será assinado
	 */
	public File getFileToBeSigned() {
		return this.file;
	}
}
