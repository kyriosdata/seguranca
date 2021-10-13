package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignaturePolicy;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.exceptions.LpaException;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;
import org.w3c.dom.*;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.Level;

/**
 * Esta classe representa uma Lista de Políticas de Assinatura (LPA)
 */
public class Lpa {

	private static final int URN_OID_STRING_LENGTH = 8;
	/**
	 * Data em que a LPA será atualizada
	 */
	private Date nextUpdate;
	/**
	 * Lista dos nomes das políticas de assinatura
	 */
	private List<String> policiesNames;
	/**
	 * Lista de descrição das políticas
	 */
	private List<String> fieldsOfApplications;
	/**
	 * Lista da data de revogação das políticas
	 */
	private List<String> revocationDates;
	/**
	 * Lista das URIs das políticas
	 */
	private List<String> textualPolicyUris;
	/**
	 * Lista dos valores de hash das políticas
	 */
	private List<String[]> textualPolicyDigests;
	/**
	 * Lista das URIs das políticas
	 */
	private List<String> artifactPolicyUris;
	/**
	 * Lista dos valores de hash das políticas
	 */
	private List<String> artifactPolicyDigests;
	/**
	 * Quantidade de políticas na LPA
	 */
	private int quantityOfPolicyInfo;
	/**
	 * Indica se a LPA é XML
	 */
	private boolean isXml;
	/**
	 * Lista de identificadores das políticas
	 */
	private List<String> policyOids;
	/**
	 * Mapeamento entre o valor de hash de uma PA e sua data de revogação
	 */
	private Map<String, String> revocatedPasByFileHash;
	/**
	 * Lista de algoritmos utilizados para cálculo de hash das políticas
	 */
	private List<String> artifactPolicyDigestsMethod;
	/**
	 * Mapeamento entre o identificador de uma política e seu objeto
	 */
	private Map<String, SignaturePolicy> downloadedPolicies;
	/**
	 * Valor de hash da última PA utilizada em validação
	 */
	private byte[] lastHash;
	/**
	 * Algoritmo de hash da última PA utilizada em validação
	 */
	private String lastDigestMethod;
	/**
	 * Índice da última PA utilizada em validação
	 */
	private int lastPaIndex;
	/**
	 * Lista de 'PolicyInfo'
	 */
	private List<PolicyInfo> policyInfoList;
	/**
	 * Mapeamento entre o nome de uma política e seu identificador
	 */
	private Map<String, String> policyNameToOid;
	/**
	 * Lista da versão das políticas
	 */
	private List<String> versions;
	/**
	 * Bytes da LPA
	 */
	private byte[] lpaBytes;
	/**
	 * Bytes da assinatura da LPA
	 */
	private byte[] signatureBytes;

	/**
	 * Construtor
	 */
	public Lpa() {
		this.policiesNames = new ArrayList<String>();
		this.fieldsOfApplications = new ArrayList<String>();
		this.policyOids = new ArrayList<String>();
		this.revocationDates = new ArrayList<String>();
		this.textualPolicyUris = new ArrayList<String>();
		this.textualPolicyDigests = new ArrayList<String[]>();
		this.artifactPolicyUris = new ArrayList<String>();
		this.artifactPolicyDigests = new ArrayList<String>();
		this.quantityOfPolicyInfo = 0;
		this.revocatedPasByFileHash = new HashMap<String, String>();
		this.downloadedPolicies = new HashMap<String, SignaturePolicy>();
		this.artifactPolicyDigestsMethod = new ArrayList<String>();
		this.policyInfoList = new ArrayList<PolicyInfo>();
		this.versions = new ArrayList<String>();
		this.lpaBytes = null;
		this.signatureBytes = null;
	}

	/**
	 * Construtor. Inicializa os atributos com os valores da LPA dada
	 * @param lpa A LPA
	 */
	public Lpa(Lpa lpa) {
		this.policiesNames = new ArrayList<String>(lpa.policiesNames);
		this.fieldsOfApplications = new ArrayList<String>(lpa.fieldsOfApplications);
		this.policyOids = new ArrayList<String>(lpa.policyOids);
		this.revocationDates = new ArrayList<String>(lpa.revocationDates);
		this.textualPolicyUris = new ArrayList<String>(lpa.textualPolicyUris);
		this.textualPolicyDigests = new ArrayList<String[]>(lpa.textualPolicyDigests);
		this.artifactPolicyUris = new ArrayList<String>(lpa.artifactPolicyUris);
		this.artifactPolicyDigests = new ArrayList<String>(lpa.artifactPolicyDigests);
		this.quantityOfPolicyInfo = lpa.quantityOfPolicyInfo;
		this.revocatedPasByFileHash = new HashMap<String, String>(lpa.revocatedPasByFileHash);
		this.artifactPolicyDigestsMethod = new ArrayList<String>(lpa.artifactPolicyDigestsMethod);
		this.versions = new ArrayList<String>(lpa.versions);
		this.lpaBytes = lpa.getLpaBytes();
		this.signatureBytes = lpa.getSignatureBytes();
	}

	/**
	 * Atribue os bytes de uma assinatura detached da LPA
	 * @param signature Stream de bytes da assinatura
	 */
	public void setSignatureBytes(InputStream signature) {
		try {
			this.signatureBytes = IOUtils.toByteArray(signature);
		} catch (IOException e) {
			Application.logger.log(Level.WARNING, "Erro ao ler os bytes da assinatura da LPA", e);
		}
	}

	/**
	 * Retorna os bytes de uma assinatura detached da LPA
	 * @return Bytes array da assinatura
	 */
	public byte[] getSignatureBytes() {
		return this.signatureBytes;
	}

	/**
	 * Faz download da LPA e inicializa os atributos
	 * @param lpaUrl A URL a ser feito o download
	 * @throws LpaException Exceção em caso de erro no arquivo obtido da URL
	 */
	public void readLpa(String lpaUrl, String detachedSignatureUrl) throws LpaException, IOException {
		readLpa(lpaUrl);
		InputStream detachedSignature = getSignatureStream(detachedSignatureUrl);
		this.setSignatureBytes(detachedSignature);
	}

	/**
	 * Inicializa os atributos da LPA a partir do conteúdo em stream de dados.
	 * @param lpa stream da LPA
	 * @param detachedSignature Stream da assinatura detached da LPA
	 * @throws LpaException Exceção em caso de erro nos dados lidos
	 */
	public void readLpa(InputStream lpa, InputStream detachedSignature) throws LpaException, IOException {
		readLpa(lpa);
		this.setSignatureBytes(detachedSignature);
	}

	/**
	 * Faz download da LPA e inicializa os atributos
	 * @param url A URL a ser feito o download
	 * @throws LpaException Exceção em caso de erro no arquivo obtido da URL
	 */
	public void readLpa(String url) throws LpaException, IOException {
		InputStream inputStream = getLpaStream(url);
		this.readLpa(inputStream);
	}

	/**
	 * Inicializa os atributos da LPA a partir do conteúdo em stream de dados.
	 * @param inputStream stream da LPA
	 * @throws LpaException Exceção em caso de erro nos dados lidos
	 */
	public void readLpa(InputStream inputStream) throws LpaException, IOException {
		this.policyNameToOid = new HashMap<String, String>();
		try {
			lpaBytes = IOUtils.toByteArray(inputStream);
			inputStream = new ByteArrayInputStream(lpaBytes);
		} catch (IOException e) {
			Application.logger.log(Level.SEVERE, "Erro ao ler os bytes da LPA", e);
		}

		int headerSize = 5;
		inputStream.mark(headerSize * headerSize);
		int readResult = -1;
		try {
			readResult = inputStream.read();
		} catch (IOException ioException) {
			throw new LpaException(
					"Não foi possível ler o conteúdo da página da LPA",
					ioException.getStackTrace());
		}
		byte[] header = null;
		if (readResult > 0) {
			header = new byte[headerSize];
			try {
				inputStream.read(header);
			} catch (IOException ioException) {
				throw new LpaException(
						"Não foi possível ler o cabeçalho da LPA",
						ioException.getStackTrace());
			}
			try {
				if (inputStream.markSupported()) {
					inputStream.reset();
				}
			} catch (IOException ioException) {
				throw new LpaException(
						"Não foi possível zerar o ponteiro dos bytes lidos da LPA.",
						ioException.getStackTrace());
			}
		}
		String headerString = new String(header);

		String xmlHeader = "?xml";

		if (headerString.contains(xmlHeader)) {
			this.isXml = true;
			getLpaFromXml();
		} else {
			this.isXml = false;
			getLpaFromAsn1();
		}

		for (int index = 0; index < this.getArtifactPolicyUris().size(); index++) {
			String policyUri = this.getArtifactPolicyUris().get(index);
			int slashIndex = policyUri.lastIndexOf("/");
			String policyName = policyUri.substring(slashIndex + 1);
			String policyOid = this.getPolicyOids().get(index);
			this.policyNameToOid.put(policyName, policyOid);
		}
	}

	/**
	 * Retorna o mapeamento entre o nome de uma política e seu identificador
	 * @return O mapeamento entre o nome de uma política e seu identificador
	 */
	public Map<String, String> getPolicyNameToOid() {
		return policyNameToOid;
	}

	/**
	 * Obtém o InputStream da assinatura da lpa.
	 *
	 * @param lpaSignatureUrl
	 *            - endereço da assinatura da lpa
	 * @return o InputStream da assinatura da lpa
	 * @throws LpaException
	 */
	public InputStream getSignatureStream(String lpaSignatureUrl) throws LpaException {
		URL signatureUrl = null;
		InputStream inputStream = null;
		try {
			signatureUrl = new URL(lpaSignatureUrl);
		} catch (MalformedURLException malformedURLException) {
			throw new LpaException(
					"A URL da assinatura está inconsistente ou mal formada.",
					malformedURLException.getStackTrace());
		}
		URLConnection urlConnection = null;
		try {
			urlConnection = signatureUrl.openConnection();
		} catch (IOException ioException) {
			throw new LpaException(
					"Impossível se conectar à pagina da assinatura indicada.",
					ioException.getStackTrace());
		}
		if (urlConnection != null) {
			boolean retry = false;
			try {
				inputStream = urlConnection.getInputStream();
			} catch (IOException ioException) {
				retry = true;
			}
			if (retry) {
				try {
					inputStream = urlConnection.getInputStream();
				} catch (IOException ioException) {
					throw new LpaException(
							"Não foi possível acessar o conteúdo da página da assinatura",
							ioException.getStackTrace());
				}
			}
		}
		return inputStream;
	}

	/**
	 * Retorna o {@link InputStream} obtido da conexão com a URL dada
	 * @param url A URL
	 * @return O {@link InputStream} obtido da conexão
	 * @throws LpaException Exceção em caso de erro no stream obtido
	 */
	public InputStream getLpaStream(String url) throws LpaException {
		URL lpaUrl = null;
		InputStream inputStream = null;
		try {
			lpaUrl = new URL(url);
		} catch (MalformedURLException malformedURLException) {
			throw new LpaException(
					"A URL da LPA informada está inconsistente ou mal formada.",
					malformedURLException.getStackTrace());
		}
		URLConnection urlConnection = null;
		try {
			urlConnection = lpaUrl.openConnection();
		} catch (IOException ioException) {
			throw new LpaException(
					"Impossível se conectar à pagina da LPA indicada.",
					ioException.getStackTrace());
		}
		if (urlConnection != null) {
			boolean retry = false;
			try {
				inputStream = urlConnection.getInputStream();
			} catch (IOException ioException) {
				retry = true;
			}
			if (retry) {
				try {
					inputStream = urlConnection.getInputStream();
				} catch (IOException ioException) {
					throw new LpaException(
							"Não foi possível acessar o conteúdo da página da LPA",
							ioException.getStackTrace());
				}
			}
		}
		return inputStream;
	}

	/**
	 * Busca as informações de uma PA XML fazendo o seu download na URL dada
	 * @param policyUri A URL
	 * @return A política de assinatura obtida
	 * @throws ParserConfigurationException Exceção em caso de erro na configuração do parser
	 * @throws SAXException Exceção em caso de erro na leitura do stream do arquivo da PA
	 * @throws DOMException Exceção em caso de erro no elemento XML
	 * @throws ParseException Exceção em caso de erro no parsing da data no atributo
	 * @throws CertificateException Exceção em caso de erro na codificação do certificado
	 * @throws IOException Exceção em caso de erro nos bytes do atributo
	 * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
	 */
	private SignaturePolicy getSignaturePolicyFromFileXML(String policyUri)
			throws ParserConfigurationException, SAXException, IOException,
			DOMException, CertificateException, NoSuchAlgorithmException,
			ParseException {
		SignaturePolicy policy = null;
		URL lpaUrl = new URL(policyUri);
		URLConnection urlConnection = lpaUrl.openConnection();
		if (urlConnection != null) {
			InputStream inputStream = urlConnection.getInputStream();
			if (inputStream == null)
				inputStream = urlConnection.getInputStream();

			byte[] buf = Streams.readAll(inputStream);

			InputStream copy = new ByteArrayInputStream(buf);

			policy = this.getSignaturePolicyFromFileXML(copy);
			policy.setEncoded(buf);
			MessageDigest digest = MessageDigest.getInstance(this
					.getHashAlgoritm());
			this.lastHash = digest.digest(buf);
		}
		return policy;
	}

	/**
	 * Retorna as informações de uma PA XML
	 * @param policyStream stream de dados da política XML
	 * @return {@link SignaturePolicy} política de assinatura
	 */
	public SignaturePolicy getSignaturePolicyFromFileXML(InputStream policyStream) throws ParserConfigurationException, SAXException, NoSuchAlgorithmException, CertificateException, ParseException, IOException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder builder = factory.newDocumentBuilder();
		Document document = builder.parse(policyStream);
		return new SignaturePolicy(document);
	}

	/**
	 * Retorna o algoritmo de hash da última PA utilizada em validação
	 * @return O algoritmo de hash da última PA utilizada em validação
	 */
	private String getHashAlgoritm() {
		return this.lastDigestMethod;
	}

	/**
	 * Busca as informações de uma PA ASN.1 fazendo o seu download na URL dada
	 * @param uri A URL
	 * @return A política de assinatura obtida
	 * @throws ParseException Exceção em caso de erro no parsing da data no atributo
	 * @throws CertificateException Exceção em caso de erro na codificação do certificado
	 * @throws IOException Exceção em caso de erro nos bytes do atributo
	 * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
	 */
	private SignaturePolicy getSignaturePolicyFromFileASN1(String uri)
			throws IOException, CertificateException, NoSuchAlgorithmException,
			ParseException {
		SignaturePolicy policy = null;
		URL lpaUrl = null;
		lpaUrl = new URL(uri);
		URLConnection urlConnection = null;
		urlConnection = lpaUrl.openConnection();
		if (urlConnection != null) {
			InputStream inputStream = null;
			inputStream = urlConnection.getInputStream();
			if (inputStream == null)
				inputStream = urlConnection.getInputStream();
			policy = this.getSignaturePolicyFromFileAsn1(inputStream);
			byte[] encoded = policy.getEncoded();
			MessageDigest digest = MessageDigest.getInstance(this.getHashAlgoritm());

			this.lastHash = digest.digest(encoded);
		}
		return policy;
	}

	/**
	 * Retorna as informações de uma PA ASN1
	 * @param policyStream stream de dados da política ASN1
	 * @return {@link SignaturePolicy} política de assinatura
	 */
	public SignaturePolicy getSignaturePolicyFromFileAsn1(InputStream policyStream) throws CertificateException, NoSuchAlgorithmException, ParseException, IOException {
		byte[] encoded = Streams.readAll(policyStream);
		return new SignaturePolicy(encoded);
	}

	/**
	 * Lê a LPA a partir dos dados carregados na classe
	 * @throws LpaException Exceção em caso de erro no stream
	 */
	private void getLpaFromAsn1() throws LpaException, IOException {
		ASN1Sequence lpaSequence = null;
		try {
			byte[] encoded = this.lpaBytes;
			lpaSequence = (ASN1Sequence) ASN1Sequence.fromByteArray(encoded);
		} catch (IOException ioException) {
			throw new LpaException(
					"Falha ao criar um ASN1Object a partir de um byte array.",
					ioException.getStackTrace());
		}
		ASN1Sequence policyInfosSequence = (ASN1Sequence) lpaSequence.getObjectAt(0);

		testVersion(policyInfosSequence);

		Enumeration<?> iterator = policyInfosSequence.getObjects();
		while (iterator.hasMoreElements()) {
			Object asn1Object = iterator.nextElement();
			if (!(asn1Object instanceof ASN1Sequence)) {
				throw new LpaException("Not a LPA file");
			}
			ASN1Sequence actualPolicyInfoSequence = (ASN1Sequence) asn1Object;
			addPolicyInfoFromActualDerObject(actualPolicyInfoSequence);
		}
		if (lpaSequence.getObjectAt(1) instanceof ASN1UTCTime) {
			ASN1UTCTime nextUpdateTime = (ASN1UTCTime) lpaSequence
					.getObjectAt(1);
			this.setNextUpdate(nextUpdateTime.getTime());
		} else {
			ASN1GeneralizedTime nextUpdateTime = (ASN1GeneralizedTime) lpaSequence
					.getObjectAt(1);
			this.setNextUpdate(nextUpdateTime.getTime());
		}

	}

	/**
	 * Verifica se a LPA tem sua versão igual a 1
	 * @param policyInfosSequence Informação de políticas codificada em ASN.1
	 * @throws LpaException Exceção caso a versão seja v1
	 */
	private void testVersion(ASN1Sequence policyInfosSequence)
			throws LpaException {

		ASN1Sequence policyInfo = ((ASN1Sequence) policyInfosSequence.getObjectAt(0));
		if (policyInfo.getObjectAt(0) instanceof DERPrintableString) {
			throw new LpaException("LPA com versão incorreta");
		}

	}

	/**
	 * Adiciona uma política a partir de sua codificação ASN.1
	 * @param policyInfoSequence A política codificada em ASN.1
	 */
	private void addPolicyInfoFromActualDerObject(ASN1Sequence policyInfoSequence) throws IOException {
		ASN1Encodable firstObject = policyInfoSequence.getObjectAt(0);
		if (firstObject instanceof DERPrintableString) {
			this.addPolicyInfoV1(policyInfoSequence);
		} else {
			this.addPolicyInfoV2(policyInfoSequence);
		}
	}

	/**
	 * Adiciona uma política do tipo V2 codificada em ASN.1
	 * @param policyInfoSequence A política codificada em ASN.1
	 */
	private void addPolicyInfoV2(ASN1Sequence policyInfoSequence) {
		String version = null;

		String[] signingPeriod = this
				.getSigningPeriodFromDerObject((ASN1Sequence) policyInfoSequence
						.getObjectAt(0));

		int hasRevocationIndex = 0;
		String revocationDate = null;
		if (policyInfoSequence.size() == 5) {
			hasRevocationIndex = 1;

			// ASN1Sequence revocationObject = (ASN1Sequence)
			// policyInfoSequence.getObjectAt(1);
			revocationDate = ((ASN1GeneralizedTime) policyInfoSequence
					.getObjectAt(1)).getTime();
		}

		int oidIndex = 1 + hasRevocationIndex;
		int uriIndex = 2 + hasRevocationIndex;
		int digestIndex = 3 + hasRevocationIndex;

		String policyOid = policyInfoSequence.getObjectAt(oidIndex).toString();

		String artifactPolicyUri = ((DERIA5String) policyInfoSequence
				.getObjectAt(uriIndex)).getString();
		ASN1Sequence policyDigests = (ASN1Sequence) policyInfoSequence
				.getObjectAt(digestIndex);

		ASN1Sequence artifactPolicyMethodDER = (ASN1Sequence) policyDigests
				.getObjectAt(0);

		String artifactPolicyDigest = this
				.getPolicyDigestFromOctets((DEROctetString) policyDigests
						.getObjectAt(1));
		String artifactPolicyMethod = artifactPolicyMethodDER.getObjectAt(0)
				.toString();

		this.addPolicyInfo(version, signingPeriod, policyOid,
				artifactPolicyUri, artifactPolicyMethod, artifactPolicyDigest,
				revocationDate);
	}

	/**
	 * Adiciona uma política do tipo V1 codificada em ASN.1
	 * @param policyInfoSequence A política codificada em ASN.1
	 */
	private void addPolicyInfoV1(ASN1Sequence policyInfoSequence) throws IOException {
		String version = null;

		String[] signingPeriod = this
				.getSigningPeriodFromDerObject((ASN1Sequence) policyInfoSequence
						.getObjectAt(2));
		String policyOid = null;

		boolean hasRevocationDate = false;
		String revocationDate = null;
		if (policyInfoSequence.getObjectAt(3) instanceof ASN1UTCTime) {
			hasRevocationDate = true;
			revocationDate = ((ASN1UTCTime) policyInfoSequence.getObjectAt(3))
					.getTime();
		}

		String artifactPolicyUri = null;
		String artifactPolicyDigest = null;

		int uriIndex = hasRevocationDate ? 4 : 3;
		int digestIndex = hasRevocationDate ? 5 : 4;
		ASN1Sequence policyUris = (ASN1Sequence) policyInfoSequence
				.getObjectAt(uriIndex);
		DERTaggedObject asn1PolicyUri = (DERTaggedObject) policyUris
				.getObjectAt(1);
		artifactPolicyUri = new String(((DEROctetString) asn1PolicyUri.getObjectParser(10, true)).getOctets());
		
		ASN1Sequence policyDigests = (ASN1Sequence) policyInfoSequence
				.getObjectAt(digestIndex);
		artifactPolicyDigest = this
				.getPolicyDigestFromDerObject((DERTaggedObject) policyDigests
						.getObjectAt(1));

		this.addPolicyInfo(version, signingPeriod, policyOid,
				artifactPolicyUri, CMSSignedDataGenerator.DIGEST_SHA1,
				artifactPolicyDigest, revocationDate);
	}

	/**
	 * Retorna o valor de hash no objeto
	 * @param policyDigestTagged O objeto ASN.1
	 * @return O valor de hash em base64
	 */
	private String getPolicyDigestFromDerObject(
			DERTaggedObject policyDigestTagged) throws IOException {
		ASN1Sequence policyDigestSequence = (ASN1Sequence) policyDigestTagged.getObjectParser(1, true);
		
		// DERObjectIdentifier derPolicyDigestOid = (DERObjectIdentifier)
		// sequence.getObjectAt(0);
		// String policyDigestOid = derPolicyDigestOid.getId();
		DEROctetString derPolicyDigestValue = (DEROctetString) policyDigestSequence.getObjectAt(1);
		return this.getPolicyDigestFromOctets(derPolicyDigestValue);
	}

	/**
	 * Retorna o valor dos octetos ASN.1 em uma string base64
	 * @param derOctetString Os octetos ASN.1
	 * @return O valor dos octetos em base64
	 */
	private String getPolicyDigestFromOctets(DEROctetString derOctetString) {
		// DEROctetString derPolicyDigestValue = (DEROctetString)
		// derOctetString.getObjectAt(1);
		String policyDigestValue = new String(Base64.encode(derOctetString
				.getOctets()));
		// String[] policyDigest = { policyDigestOid, policyDigestValue };
		return policyDigestValue;
	}

	/**
	 * Retorna o valor da URI no objeto ASN.1
	 * @param uriSequence O objeto ASN.1
	 * @param index Índice da URI no objeto
	 * @return A URI
	 */
	private String getUriFromDerObject(ASN1Sequence uriSequence, int index) throws IOException {
		DERTaggedObject derArtifactPolicyUri = (DERTaggedObject) uriSequence.getObjectAt(index);
		DEROctetString artifactPolicyUri = (DEROctetString) derArtifactPolicyUri.getObjectParser(BERTags.IA5_STRING, true);
		
		String policyUri = new String(artifactPolicyUri.getOctets());
		return policyUri;
	}

	/**
	 * Retorna o período de validade da PA a partir do objeto ASN.1
	 * @param signingPeriodSequence O objeto ASN.1
	 * @return O período de validade da PA
	 */
	private String[] getSigningPeriodFromDerObject(
			ASN1Sequence signingPeriodSequence) {
		ASN1GeneralizedTime derNorBefore = (ASN1GeneralizedTime) signingPeriodSequence
				.getObjectAt(0);
		ASN1GeneralizedTime derNorAfter = (ASN1GeneralizedTime) signingPeriodSequence
				.getObjectAt(1);
		String[] signingPeriod = { derNorBefore.getTime(),
				derNorAfter.getTime() };
		return signingPeriod;
	}

	/**
	 * Retorna a descrição da PA a partir do objeto ASN.1
	 * @param policyInfoSequence O objeto ASN.1
	 * @return A descrição da PA
	 */
	private String getFieldOfApplicationFromDerObject(
			ASN1Sequence policyInfoSequence) {
		DERUTF8String derFieldOfApplication = (DERUTF8String) policyInfoSequence
				.getObjectAt(1);
		String fieldOfApplication = derFieldOfApplication.getString();
		return fieldOfApplication;
	}

	/**
	 * Retorna o nome da política a partir do objeto ASN.1
	 * @param policyInfoSequence O objeto ASN.1
	 * @return O nome da política
	 */
	private String getPolicyNameFromDerObject(ASN1Sequence policyInfoSequence) {
		DERPrintableString derPolicyName = (DERPrintableString) policyInfoSequence
				.getObjectAt(0);
		String policyName = derPolicyName.getString();
		return policyName;
	}

	/**
	 * Lê a LPA XML a partir dos dados carregados na classe
	 * @throws LpaException Exceção em caso de erro no stream
	 */
	private void getLpaFromXml() throws LpaException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		factory.setIgnoringElementContentWhitespace(true);
		DocumentBuilder builder = null;
		Document document = null;

		try {
			builder = factory.newDocumentBuilder();
		} catch (ParserConfigurationException parserConfigurationException) {
			throw new LpaException(parserConfigurationException);
		}

		try {
			document = builder.parse(new ByteArrayInputStream(this.lpaBytes));
		} catch (SAXException saxException) {
			throw new LpaException(saxException);
		} catch (IOException ioException) {
			throw new LpaException(ioException);
		}

		document.getDocumentElement().normalize();

		NodeList nextUpdateList = document.getDocumentElement()
				.getElementsByTagName("lpa:NextUpdate");
		if (nextUpdateList.getLength() == 0) {
			throw new LpaException("Not a LPA file");
		}
		this.setNextUpdate(nextUpdateList.item(0).getTextContent());

		NodeList policyInfoList = document.getDocumentElement()
				.getElementsByTagName("lpa:PolicyInfo");
		for (int i = 0; i < policyInfoList.getLength(); i++) {
			addPolicyInfoExtractedFromActualNode((Element) policyInfoList
					.item(i));
		}
	}

	/**
	 * Retorna a política de assinatura correspondente ao identificador dado
	 * @param signaturePolicyIdentifier O identificador da política
	 * @return A política de assinatura
	 * @throws LpaException Exceção em caso de erro na leitura do arquivo da PA
	 */
	public SignaturePolicy getSignaturePolicy(String signaturePolicyIdentifier)
			throws LpaException {
		SignaturePolicy policy = null;
		if (this.downloadedPolicies.get(signaturePolicyIdentifier) == null) {
			int policyIndex = -1;
			boolean found = false;
			int i = 0;

			while (!found && i < this.policyOids.size()) {
				String actualValue = this.policyOids.get(i);
				if (signaturePolicyIdentifier.contains("urn:oid:"))
					signaturePolicyIdentifier = signaturePolicyIdentifier.substring(8);
				if (actualValue.compareToIgnoreCase(signaturePolicyIdentifier) == 0) {
					policyIndex = i;
					found = true;
				} else
					i++;
			}
			if (policyIndex < 0) {
				throw new LpaException("Não existe PA cadastrada com tal resumo criptográfico.");
			}
			String digestMethod = this.artifactPolicyDigestsMethod.get(policyIndex);

			this.lastDigestMethod = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(digestMethod);
		
			String policyUri = this.artifactPolicyUris.get(policyIndex);
			this.lastPaIndex = policyIndex;
			if (this.isXml) {
				try {
					policy = getSignaturePolicyFromFileXML(policyUri);
				}  catch (DOMException domException) {
					throw new LpaException(domException);
				} catch (CertificateException certificateException) {
					throw new LpaException(certificateException);
				} catch (NoSuchAlgorithmException noSuchAlgorithmException) {
					throw new LpaException(noSuchAlgorithmException);
				} catch (ParserConfigurationException parserConfigurationException) {
					throw new LpaException(parserConfigurationException);
				} catch (SAXException saxException) {
					throw new LpaException(saxException);
				} catch (IOException ioException) {
					throw new LpaException(ioException);
				} catch (ParseException parseException) {
					throw new LpaException(parseException);
				}
			} else {
				try {
					policy = getSignaturePolicyFromFileASN1(policyUri);
				} catch (CertificateException certificateException) {
					throw new LpaException(certificateException);
				} catch (NoSuchAlgorithmException noSuchAlgorithmException) {
					throw new LpaException(noSuchAlgorithmException);
				} catch (IOException ioException) {
					throw new LpaException(ioException);
				} catch (ParseException parseException) {
					throw new LpaException(parseException);
				}
			}
			this.downloadedPolicies.put(signaturePolicyIdentifier, policy);
		} else {
			policy = this.downloadedPolicies.get(signaturePolicyIdentifier);
		}
		return policy;
	}

	/**
	 * Adiciona uma política codificada em XML
	 * @param actualPolicyInfoElement O nodo XML da política
	 */
	private void addPolicyInfoExtractedFromActualNode(
			Element actualPolicyInfoElement) {
		NodeList policyOidList = actualPolicyInfoElement
				.getElementsByTagName("XAdES:Identifier");
		String policyOid = null;
		boolean newerLpa = false;
		if (policyOidList.getLength() > 0) { // Newer version of the LPA
			newerLpa = true;
			policyOid = policyOidList.item(0).getFirstChild().getNodeValue()
					.substring(URN_OID_STRING_LENGTH);
		}

		String[] signingPeriod = getSigningPeriodFromNode(actualPolicyInfoElement);
		NodeList revocationDateList = actualPolicyInfoElement
				.getElementsByTagName("lpa:RevocationDate");
		String revocationDate = null;
		if (revocationDateList.getLength() > 0) {
			revocationDate = revocationDateList.item(0).getTextContent();
		}

		NodeList xmlPolicyDigestAndUriList = actualPolicyInfoElement
				.getElementsByTagName("lpa:PolicyDigestAndURI");
		String xmlPolicyDigest = null;
		String xmlPolicyUri = null;
		String algValue = null;
		if (xmlPolicyDigestAndUriList.getLength() > 0) {
			int index = xmlPolicyDigestAndUriList.getLength() == 1 ? 0 : 1;
			xmlPolicyDigest = getPolicyDigestFromElement((Element) xmlPolicyDigestAndUriList
					.item(index));
			xmlPolicyUri = getPolicyUriFromElement((Element) xmlPolicyDigestAndUriList
					.item(index));
			algValue = getPolicyAlgFromElement((Element) xmlPolicyDigestAndUriList
					.item(index));
		}

		String version = null;
		if (newerLpa) {
			NodeList versionList = actualPolicyInfoElement.getParentNode()
					.getChildNodes();
			version = versionList.item(1).getTextContent();
		}

		// this.addPolicyInfo(version, signingPeriod, policyOid, xmlPolicyUri,
		// xmlPolicyDigest, revocationDate);
		this.addPolicyInfo(version, signingPeriod, policyOid, xmlPolicyUri,
				algValue, xmlPolicyDigest, revocationDate);
	}

	/**
	 * Retorna o valor de resumo criptográfico da política a partir do nodo XML
	 * @param digestAndUri O nodo XML
	 * @return O valor de hash da política
	 */
	private String getPolicyDigestFromElement(Element digestAndUri) {
		NodeList digestList = digestAndUri
				.getElementsByTagName("lpa:PolicyDigest");
		Element digest = (Element) digestList.item(0);
		return digest.getElementsByTagName("lpa:DigestValue").item(0)
				.getTextContent();
	}

	/**
	 * Retorna o algoritmo de resumo criptográfico da política a partir do nodo XML
	 * @param digestAndUri O nodo XML
	 * @return O algoritmo de cálculo de hash da política
	 */
	private String getPolicyAlgFromElement(Element digestAndUri) {
		NodeList digestList = digestAndUri
				.getElementsByTagName("lpa:PolicyDigest");
		Element digest = (Element) digestList.item(0);
		return digest.getElementsByTagName("lpa:DigestMethod").item(0)
				.getAttributes().getNamedItem("Algorithm").getNodeValue();
	}

	/**
	 * Retorna a URI da política a partir do nodo XML
	 * @param digestAndUri O nodo XML
	 * @return A URI da política
	 */
	private String getPolicyUriFromElement(Element digestAndUri) {
		NodeList uri = digestAndUri.getElementsByTagName("lpa:PolicyURI");
		return uri.item(0).getTextContent();
	}

	/**
	 * Retorna o período de validade da política a partir do nodo XML
	 * @param actualPolicyInfoElement O nodo XML
	 * @return O período de validade da política
	 */
	private String[] getSigningPeriodFromNode(Element actualPolicyInfoElement) {
		Element signingPeriodNode = (Element) actualPolicyInfoElement
				.getElementsByTagName("lpa:SigningPeriod").item(0);
		Node notBeforeNode = signingPeriodNode.getElementsByTagName(
				"lpa:NotBefore").item(0);
		NodeList notAfterList = signingPeriodNode
				.getElementsByTagName("lpa:NotAfter");
		String[] signingPeriod = { "", "" };
		if (notAfterList.getLength() > 0) { // not after is optional
			Node notAfterNode = notAfterList.item(0);
			signingPeriod[0] = notBeforeNode.getTextContent();
			signingPeriod[1] = notAfterNode.getTextContent();
		} else {
			signingPeriod[0] = notBeforeNode.getTextContent();
		}
		return signingPeriod;
	}

	/**
	 * Retorna a descrição da política a partir do nodo XML
	 * @param actualPolicyInfoElement O nodo XML
	 * @return A descrição da política
	 */
	private String getFieldOfApplicationFromNode(Element actualPolicyInfoElement) {
		Node fieldOfApplicationNode = actualPolicyInfoElement
				.getElementsByTagName("").item(1);
		String fieldOfApplication = fieldOfApplicationNode.getTextContent();
		return fieldOfApplication;
	}

	/**
	 * Retorna o nome da política a partir do nodo XML
	 * @param actualPolicyInfoElement O nodo XML
	 * @return O nome da política
	 */
	private String getPolicyNameFromNode(Element actualPolicyInfoElement) {
		Node policyNameNode = actualPolicyInfoElement.getElementsByTagName(
				"lpa:PolicyName").item(0);
		String policyName = policyNameNode.getTextContent();
		return policyName;
	}

	// public void addPolicyInfo(String version, String[] signingPeriod, String
	// policyOid, String artifactPolicyUri,
	// String artifactPolicyDigest, String textualPolicyDigest, String
	// revocationDate) {
	// // this.policiesNames.add(policyName);
	// // this.fieldsOfApplications.add(fieldOfApplication);
	// this.versions.add(version);
	// this.signingPeriods.add(signingPeriod);
	// this.policyOids.add(policyOid);
	// this.revocationDates.add(revocationDate);
	// // this.textualPolicyUris.add(textualPolicyUri);
	// this.textualPolicyDigestsMethod.add(textualPolicyDigest);
	// this.artifactPolicyUris.add(artifactPolicyUri);
	// this.artifactPolicyDigests.add(artifactPolicyDigest);
	// this.quantityOfPolicyInfo++;
	//
	// if (revocationDate != null) {
	// this.revocatedPasByFileHash.put(artifactPolicyDigest, revocationDate);
	// }
	// }

	/**
	 * Adiciona as informações de uma política às listas e mapas
	 * @param version Versão da política
	 * @param signingPeriod Período de validade da política
	 * @param policyOid O identificador da política
	 * @param artifactPolicyUri A URI da política
	 * @param artifactPolicyDigestMethod O algoritmo de hash da política
	 * @param artifactPolicyDigest O valor de hash da política
	 * @param revocationDate A data de revogação da política
	 */
	public void addPolicyInfo(String version, String[] signingPeriod, String policyOid, String artifactPolicyUri,
            String artifactPolicyDigestMethod, String artifactPolicyDigest, String revocationDate) {
        // this.policiesNames.add(policyName);
        // this.fieldsOfApplications.add(fieldOfApplication);
        this.versions.add(version);
//        this.signingPeriods.add(signingPeriod);
        this.policyOids.add(policyOid);
        this.revocationDates.add(revocationDate);
        // this.textualPolicyUris.add(textualPolicyUri);
        // this.textualPolicyDigests.add(textualPolicyDigest);
        int lastSeparator = artifactPolicyUri.lastIndexOf('/');
        this.policiesNames.add(artifactPolicyUri.substring(lastSeparator + 1));
        this.artifactPolicyUris.add(artifactPolicyUri);
        this.artifactPolicyDigestsMethod.add(artifactPolicyDigestMethod);
        this.artifactPolicyDigests.add(artifactPolicyDigest);
        this.quantityOfPolicyInfo++;

        if (revocationDate != null) {
            this.revocatedPasByFileHash.put(artifactPolicyDigest, revocationDate);
        }

		addPolicyInfoToList(version, signingPeriod, policyOid, artifactPolicyUri, artifactPolicyDigestMethod,
				artifactPolicyDigest, revocationDate);
    }

	/**
	 * Adiciona as informações na lista de 'PolicyInfo'
	 * @param version Versão da política
	 * @param signingPeriod Período de validade da política
	 * @param policyOid O identificador da política
	 * @param artifactPolicyUri A URI da política
	 * @param artifactPolicyDigestMethod O algoritmo de hash da política
	 * @param artifactPolicyDigest O valor de hash da política
	 * @param revocationDate A data de revogação da política
	 */
	private void addPolicyInfoToList(String version, String[] signingPeriod, String policyOid, String artifactPolicyUri,
			String artifactPolicyDigestMethod, String artifactPolicyDigest, String revocationDate) {
		PolicyInfo info = new PolicyInfo(version, signingPeriod, policyOid, artifactPolicyUri, artifactPolicyDigest,
				artifactPolicyDigestMethod, revocationDate);
		this.policyInfoList.add(info);
	}

	/**
	 * Retorna a data de próxima atualização da LPA
	 * @return A data de próxima atualização da LPA
	 */
	public Date getNextUpdate() {
		return nextUpdate;
	}

	/**
	 * Atribue a data de próxima atualização da LPA
	 * @param nextUpdate A nova data de atualização
	 * @throws LpaException Exceção em caso de erro na formatação da data
	 */
	public void setNextUpdate(String nextUpdate) throws LpaException {
		SimpleDateFormat dataFormat = null;
		GregorianCalendar obtainedTime = new GregorianCalendar();
		if (isXml) {
			dataFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS");
			try {
				obtainedTime.setTime(dataFormat.parse(nextUpdate));
			} catch (ParseException parseException) {
				throw new LpaException("Ocorreu um erro de parsing");
			}
		} else {
			dataFormat = new SimpleDateFormat("yyyyMMddHHmmss");
			try {
				obtainedTime.setTime(dataFormat.parse(nextUpdate));
			} catch (ParseException parseException) {
				dataFormat = new SimpleDateFormat("yyMMddHHmmss");
				try {
					obtainedTime.setTime(dataFormat.parse(nextUpdate));
				} catch (ParseException parseException2) {
					throw new LpaException("Ocorreu um erro de parsing");
				}
			}
		}
		obtainedTime.setTimeZone(TimeZone.getTimeZone("UTC"));
		this.nextUpdate = obtainedTime.getTime();
	}

	/**
	 * Retorna a lista de nomes das políticas
	 * @return A lista de nomes das políticas
	 */
	public List<String> getPoliciesNames() {
		return policiesNames;
	}

	/**
	 * Atribue a lista de nomes das políticas
	 * @param policiesNames A lista de nomes das políticas
	 */
	public void setPoliciesNames(List<String> policiesNames) {
		this.policiesNames = policiesNames;
	}

	/**
	 * Retorna a lista de descrições das políticas
	 * @return A lista de descrições das políticas
	 */
	public List<String> getFieldsOfApplications() {
		return fieldsOfApplications;
	}

	/**
	 * Atribue a lista de descrições das políticas
	 * @param fieldsOfApplications A lista de descrições das políticas
	 */
	public void setFieldsOfApplications(List<String> fieldsOfApplications) {
		this.fieldsOfApplications = fieldsOfApplications;
	}

	/**
	 * Retorna a lista de períodos de validade das políticas
	 * @return A lista de períodos de validade das políticas
	 */
	public List<String[]> getSigningPeriods() {
		List<String[]> signingPeriods = new ArrayList<String[]>();
		for (PolicyInfo policyInfo : policyInfoList) {
			signingPeriods.add(policyInfo.getSigningPeriods());
		}
		return signingPeriods;
	}

	// TODO if necessary
	// public void setSigningPeriods(List<String[]> signingPeriods) {
	//
	// }

	/**
	 * Retorna a lista de datas de revogação
	 * @return A lista de datas de revogação
	 */
	public List<String> getRevocationDates() {
		return revocationDates;
	}

	/**
	 * Atribue a lista de datas de revogação
	 * @param revocationDates  A lista de datas de revogação
	 */
	public void setRevocationDates(List<String> revocationDates) {
		this.revocationDates = revocationDates;
	}

	/**
	 * Retorna a lista de URIs das políticas
	 * @return A lista de URIs das políticas
	 */
	public List<String> getTextualPolicyUris() {
		return textualPolicyUris;
	}

	/**
	 * Atribue a lista de URIs das políticas
	 * @param textualPolicyUris  A lista de URIs das políticas
	 */
	public void setTextualPolicyUris(List<String> textualPolicyUris) {
		this.textualPolicyUris = textualPolicyUris;
	}

	/**
	 * Retorna a lista de valores de hash das políticas
	 * @return A lista de valores de hash das políticas
	 */
	public List<String[]> getTextualPolicyDigests() {
		return textualPolicyDigests;
	}

	/**
	 * Atribue a lista de valores de hash das políticas
	 * @param textualPolicyDigests A lista de valores de hash das políticas
	 */
	public void setTextualPolicyDigests(List<String[]> textualPolicyDigests) {
		this.textualPolicyDigests = textualPolicyDigests;
	}

	/**
	 * Retorna a lista de URIs das políticas
	 * @return A lista de URIs das políticas
	 */
	public List<String> getArtifactPolicyUris() {
		return artifactPolicyUris;
	}

	/**
	 * Atribue a lista de URIs das políticas
	 * @param artifactPolicyUris  A lista de URIs das políticas
	 */
	public void setArtifactPolicyUris(List<String> artifactPolicyUris) {
		this.artifactPolicyUris = artifactPolicyUris;
	}

	/**
	 * Retorna a lista de valores de hash das políticas
	 * @return A lista de valores de hash das políticas
	 */
	public List<String> getArtifactPolicyDigests() {
		return artifactPolicyDigests;
	}

	/**
	 * Atribue a lista de valores de hash das políticas
	 * @param artifactPolicyDigests A lista de valores de hash das políticas
	 */
	public void setArtifactPolicyDigests(List<String> artifactPolicyDigests) {
		this.artifactPolicyDigests = artifactPolicyDigests;
	}

	/**
	 * Retorna a quantidade de políticas na LPA
	 * @return A quantidade de políticas na LPA
	 */
	public int getQuantityOfPolicyInfo() {
		return quantityOfPolicyInfo;
	}

	/**
	 * Atribue a quantidade de políticas na LPA
	 * @param quantityOfPolicyInfo  A quantidade de políticas na LPA
	 */
	public void setQuantityOfPolicyInfo(int quantityOfPolicyInfo) {
		this.quantityOfPolicyInfo = quantityOfPolicyInfo;
	}

	/**
	 * Informa se a LPA é XML
	 * @return Indica se a LPA é XML
	 */
	public boolean isXml() {
		return this.isXml;
	}

	/**
	 * Retorna a lista de algoritmos utilizados para cálculo de hash das políticas
	 * @return A lista de algoritmos utilizados para cálculo de hash das políticas
	 */
	public List<String> getTextualPolicyDigestsMethod() {
		return this.artifactPolicyDigestsMethod;
	}

	/**
	 * Retorna a lista de identificadores das políticas
	 * @return A lista de identificadores das políticas
	 */
	public List<String> getPolicyOids() {
		return this.policyOids;
	}

	/**
	 * Atribui as informações de uma política na LPA como a última política carregada.
	 * @param signaturePolicy Política de assinatura
	 */
	public void setLastPolicy(SignaturePolicy signaturePolicy) throws NoSuchAlgorithmException {
		String oid = signaturePolicy.getSignPolicyInfo().getSignPolicyIdentifier();
		for (int i = 0; i < this.policyOids.size(); i++) {
			if (policyOids.get(i).equals(oid)) {
				String digestMethod = this.artifactPolicyDigestsMethod.get(i);
				this.lastDigestMethod = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(digestMethod);
				MessageDigest digest = MessageDigest.getInstance(digestMethod);
				this.lastHash = digest.digest(signaturePolicy.getEncoded());
				this.lastPaIndex = i;
				return;
			}
		}
	}

	/**
	 * Verifica se uma PA é válida
	 * @return Indica se a PA é válida
	 */
	public boolean isPaValid() {

		byte[] hashInLpa = Base64.decode(this.artifactPolicyDigests.get(this.lastPaIndex));

		if (this.lastHash.length == hashInLpa.length) {
			int i = 0;
			boolean equals = true;
			while (equals && i < this.lastHash.length) {
				equals &= this.lastHash[i] == hashInLpa[i];
				i++;
			}

			return equals;
		}
		return false;
	}

	/**
	 * Verifica se a PA foi revogada
	 * @param policyOid O identificador da política
	 * @return Indica se a PA foi revogada
	 */
	public boolean isRevoked(String policyOid) {
		boolean hasRevocationDate = false;
		for (PolicyInfo policyInfo : this.policyInfoList) {
			if (policyInfo.getPolicyOid().equals(policyOid)) {
				hasRevocationDate = policyInfo.getRevocationDate() != null;
				return hasRevocationDate;
			}
		}
		return false;
	}

	public byte[] getLpaBytes() {
		return lpaBytes;
	}

	/**
	 * Atribue os bytes da LPA
	 * @param lpaBytes Os bytes da LPA
	 */
	public void setLpa(byte[] lpaBytes) {
		this.lpaBytes = lpaBytes;
	}

	/**
	 * Retorna os bytes da assinatura da LPA
	 * @param url A URL que contém o arquivo de assinatura da LPA
	 * @return Os bytes da assinatura da LPA
	 */
	public byte[] getSignatureBytes(String url) {
		try {
			return IOUtils.toByteArray(getSignatureStream(url));
		} catch (LpaException | IOException e) {
			Application.logger.log(Level.SEVERE, e.getMessage(), e);
		}
		return null;
	}
}
