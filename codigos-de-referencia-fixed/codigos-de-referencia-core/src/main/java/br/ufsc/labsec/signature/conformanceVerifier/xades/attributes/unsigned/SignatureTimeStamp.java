/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.exceptions.*;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import br.ufsc.labsec.signature.CertificateCollection;
import br.ufsc.labsec.signature.tsa.TimeStampVerifierInterface;
import br.ufsc.labsec.signature.conformanceVerifier.report.TimeStampReport;
import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractVerifier;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.xades.NamespacePrefixMapperImp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.TimeStampException;

/**
 * Representa o carimbo do tempo sobre a assinatura.
 * 
 * Esquema do atributo SignatureTimeStamp retirado do ETSI TS 101 903:
 * 
 * {@code
 * <xsd:element name="SignatureTimeStamp" type="XAdESTimeStampType"/>
 * }
 */
public class SignatureTimeStamp extends TimeStamp implements SignatureAttribute {

	private static final String FALHA_AO_VALIDAR_O_ATRIBUTO_CARIMBO_DE_TEMPO_CARIMBADORA = "Falha ao validar o atributo carimbo de tempo. Carimbadora: ";
	public static final String IDENTIFIER = "SignatureTimeStamp";

	/**
	 * Construtor usado para instanciar um ou mais carimbos do tempo de uma
	 * assinatura
	 * @param signatureVerifier Usado para criar e verificar o atributo
	 * @param index Índice do atributo. Este parâmetro é usado para atributos
	 *                 que podem aparecer mais de uma vez
	 * 
	 * @throws SignatureAttributeException
	 */
	public SignatureTimeStamp(AbstractVerifier signatureVerifier, Integer index)
			throws SignatureAttributeException {
		super(signatureVerifier);
		Element genericEncoding = signatureVerifier.getSignature()
				.getEncodedAttribute(this.getIdentifier(), index);
		this.decode(genericEncoding);
	}

	/**
	 * Construtor usado para criar um novo carimbo do tempo
	 * @param contentInfo O conteúdo do carimbo do tempo
	 */
	public SignatureTimeStamp(ContentInfo contentInfo) {
		this.contentInfo = contentInfo;
	}

	/**
	 * Decodifica o atributo para adição de atributos ou obtenção de dados do
	 * carimbo do tempo
	 * @param attributeEncoded O atributo codificado
	 * @throws EncodingException
	 * @throws SignatureAttributeException
	 */
	public SignatureTimeStamp(Element attributeEncoded)
			throws SignatureAttributeException {
		this.decode(attributeEncoded);
	}

	/**
	 * Constrói um objeto {@link SignatureTimeStamp}
	 * @param genericEncoding O atributo codificado
	 * @throws SignatureAttributeException
	 */
	protected void decode(Element genericEncoding)
			throws SignatureAttributeException {
		Element timestampNode = genericEncoding;

		NodeList encapsulatedTimeStampList;
		encapsulatedTimeStampList = timestampNode.getElementsByTagNameNS(
				NamespacePrefixMapperImp.XADES_NS, "EncapsulatedTimeStamp");
		try {
			this.contentInfo = ContentInfo.getInstance((ASN1Sequence) DERSequence.fromByteArray(Base64
							.decode(encapsulatedTimeStampList.item(0)
									.getTextContent())));
		} catch (DOMException domException) {
			throw new SignatureAttributeException(domException.getMessage(),
					domException.getStackTrace());
		} catch (IOException ioException) {
			throw new SignatureAttributeException(ioException.getMessage(),
					ioException.getStackTrace());
		}
	}

	/**
	 * Retorna o identificador do atributo
	 * @return O identificador do atributo
	 */
	@Override
	public String getIdentifier() {
		return SignatureTimeStamp.IDENTIFIER;
	}

	/**
	 * Valida o atributo em seu próprio contexto de validação. Os casos de
	 * retorno negativo dessa validação são indicados por exceções. Para efetuar
	 * esta validação é necessário adicionar os certificados do caminho de
	 * certificação da carimbadora no {@link CertStore} da classe
	 * {@link br.ufsc.labsec.signature.Verifier}. O resultado da validação é adicionado ao relatório
	 * de carimbo de tempo dado.
	 * @param report O relatório de verificação do carimbo de tempo
	 * @param stamps Lista de carimbos de tempo
	 * @throws PbadException
	 */
	//FIXME rever como são essas exceções. 
	@Override
	public void validate(TimeStampReport report, List<TimeStamp> stamps) throws PbadException {
		report.setTimeStampIdentifier(this.getIdentifier());
		report.setSchema(SignatureReport.SchemaState.VALID);
		PbadException exceptionToThrow = null;
		TimeStampToken timeStampToken = null;
		AIAException aiaException = null;
		try {
			timeStampToken = this.buildTimeStampToken();
		} catch (TimeStampException e) {
			exceptionToThrow = e;
			report.setSchema(SignatureReport.SchemaState.INVALID);
		}

		Security.addProvider(new BouncyCastleProvider());

		TimeStampVerifierInterface timeStampVerifier = null;
		try {
			timeStampVerifier = makeTimeStampVerifier(stamps);
		} catch (IOException e1) {
			throw new PbadException(e1);
		}
		try {
			timeStampVerifier.setupValidationData(report);
		} catch (AIAException e) {
			aiaException = e;
		}

		List<CertificateCollection> certList = this.signatureVerifier
				.getXadesSignatureComponent().certificateCollection;

		Certificate timeStampCertificate = null;
		int i = 0;

		while (i < certList.size() && timeStampCertificate == null) {
			X509CertSelector selector = new X509CertSelector();
			try {
				selector.setIssuer(new X500Principal(timeStampToken.getSID()
						.getIssuer().getEncoded()));
			} catch (IOException e) {
				throw new PbadException(e);
			}
			selector.setSerialNumber(timeStampToken.getSID().getSerialNumber());
			timeStampCertificate = (X509Certificate) certList.get(i)
					.getCertificate(selector);
			i++;
		}

		List<Certificate> certificateOfTimeStampTokenSidList;

		certificateOfTimeStampTokenSidList = Collections
				.singletonList(timeStampCertificate);

		if (certificateOfTimeStampTokenSidList.size() == 0) {
			SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
					"Os certificados do caminho de certificação do carimbo do tempo não foram encontrados");
			signatureAttributeException.setCritical(this.isSigned());
			exceptionToThrow = signatureAttributeException;
		} else {
			X509Certificate timeStampAutorityCert = (X509Certificate) certificateOfTimeStampTokenSidList
					.get(0);
			if (timeStampAutorityCert != null) {
				report.setSignerSubjectName(timeStampAutorityCert
						.getSubjectX500Principal().toString());
			} else {
				report.setSignerSubjectName("Certificado não encontrado.");
			}
		}

		report.setTimeReference(this.getTimeReference());
		
		X509Certificate timeStampAutorityCert = (X509Certificate) certificateOfTimeStampTokenSidList
				.get(0);
		try {
			if (timeStampAutorityCert != null) {
				if (!timeStampToken
						.isSignatureValid(this
								.createSignerInformationVerifier(timeStampAutorityCert))) {
					SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
							"Carimbo de tempo inválido. Carimbadora: "
									+ timeStampAutorityCert
											.getSubjectX500Principal());
					signatureAttributeException.setCritical(this.isSigned());
					SignerInformationVerifier s = new SignerInformationVerifier(
							null, null, null, null);
					report.setAsymmetricCipher(false);
					exceptionToThrow = signatureAttributeException;
				} else {
					report.setAsymmetricCipher(true);
				}
			} else {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Não foi possível encontrar o certificado da carimbadora.");
				exceptionToThrow = signatureAttributeException;
				report.setAsymmetricCipher(false);
			}
		} catch (TSPException tspException) {
			SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
					"Carimbo de tempo inválido", tspException.getStackTrace());
			signatureAttributeException.setCritical(this.isSigned());
			exceptionToThrow = signatureAttributeException;
		} catch (OperatorCreationException operatorCreationException) {
			TimeStampException timeStampException = new TimeStampException(
					FALHA_AO_VALIDAR_O_ATRIBUTO_CARIMBO_DE_TEMPO_CARIMBADORA
							+ timeStampAutorityCert.getSubjectX500Principal(),
					operatorCreationException);
			timeStampException.setCritical(this.isSigned());
			exceptionToThrow = timeStampException;
		} catch (CMSException cmsException) {
			TimeStampException timeStampException = new TimeStampException(
					FALHA_AO_VALIDAR_O_ATRIBUTO_CARIMBO_DE_TEMPO_CARIMBADORA
							+ timeStampAutorityCert.getSubjectX500Principal(),
					cmsException);
			timeStampException.setCritical(this.isSigned());
			exceptionToThrow = timeStampException;
		}

		byte[] messageImprintBytes = timeStampToken.getTimeStampInfo().getMessageImprintDigest();
		String hashAlgorithmId = timeStampToken.getTimeStampInfo().getMessageImprintAlgOID().getId();
		byte[] signatureHash = new byte[0];
		try {
			signatureHash = this.getHashFromSignature(hashAlgorithmId);
		} catch (PbadException signatureException) {
			SignatureAttributeException signatureAttributeException = new TimeStampException(signatureException.getMessage());
			signatureAttributeException.setCritical(this.isSigned());
			exceptionToThrow = signatureAttributeException;
		}

		report.setHash(MessageDigest.isEqual(signatureHash, messageImprintBytes));

		this.verifyAttributes(report, timeStampVerifier);

		if (aiaException != null) {
			report.setCertificationPathMessage(aiaException.getMessage());
		}

		if (exceptionToThrow != null) {
			throw exceptionToThrow;
		}
	}

	/**
	 * Realiza a verificação dos atributos do carimbo
	 * @param report O relatório de verificação do carimbo
	 * @param verifier O verificador a ser utilizado na operação do carimbo
	 * @throws SignatureAttributeException
	 */
	private void verifyAttributes(TimeStampReport report,
			TimeStampVerifierInterface verifier) throws SignatureAttributeException {
		try {
			if (!verifier.verify(report)) {
				TimeStampException timeStampException = null;
				if (verifier.getValidationErrors().size() == 1 &&
						!report.getCertPathState().equals(SignatureReport.CertValidity.Expired.toString())) {
					timeStampException = new TimeStampException(
							verifier.getValidationErrors().get(0).getMessage(), verifier.getValidationErrors().get(0));
				} else {
					timeStampException = new TimeStampException(
							verifier.getValidationErrors(), this.getIdentifier());
				}
				timeStampException.setCritical(this.isSigned());
				throw timeStampException;
			}
		} catch (TimeStampException timeStampException) {
			timeStampException.setCritical(false);
			throw timeStampException;
		}  catch (NotInICPException e) {
			throw e;
		}
	}

	/**
	 * Cria um objeto {@link TimeStampVerifierInterface}
	 * @param stamps A lista de carimbos de tempo
	 * @return O objeto criado
	 * @throws TimeStampException
	 * @throws IOException
	 */
	private TimeStampVerifierInterface makeTimeStampVerifier(List<TimeStamp> stamps)
			throws TimeStampException, IOException {
		List<String> oidStamps = new ArrayList<>();
		for (TimeStamp ts: stamps) {
			oidStamps.add(ts.getIdentifier());
		}
		TimeStampVerifierInterface verifier = this.signatureVerifier
				.getXadesSignatureComponent().timeStampVerifier;
		verifier.setTimeStamp(this.contentInfo.toASN1Primitive().getEncoded(),
				this.getIdentifier(), this.signatureVerifier.getSignaturePolicy(),
				this.signatureVerifier.getTimeReference(),oidStamps, this.isLast());

		return verifier;

	}

	/**
	 * Retorna se o carimbo de tempo é o último da assinatura
	 * @return Indica se o carimbo é o último na assinatura
	 * @throws TimeStampException
	 */
	protected boolean isLast() throws TimeStampException {
		return false;
	}

	/**
	 * Gera um {@link SignerInformationVerifier}
	 * @param certificate Certificado final do caminho de certificação que se deseja
	 *            validar
	 * @return O objeto {@link SignerInformationVerifier} criado
	 * @throws OperatorCreationException
	 * @throws CMSException
	 */
	protected SignerInformationVerifier createSignerInformationVerifier(
			X509Certificate certificate) throws OperatorCreationException,
			CMSException {
		JcaContentVerifierProviderBuilder contentVerifierProviderBuilder = new JcaContentVerifierProviderBuilder();
		ContentVerifierProvider contentVerifierProvider = contentVerifierProviderBuilder
				.build(certificate);
		DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder()
				.setProvider("BC").build();

		CMSSignatureAlgorithmNameGenerator cmsSignatureAlgorithmNameGenerator = new DefaultCMSSignatureAlgorithmNameGenerator();
        SignatureAlgorithmIdentifierFinder signatureAlgorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();

		return new SignerInformationVerifier(
				cmsSignatureAlgorithmNameGenerator,
				signatureAlgorithmIdentifierFinder, contentVerifierProvider,
				digestCalculatorProvider);
	}

	/**
	 * Retorna o atributo codificado
	 * @return O atributo em formato de nodo XML
	 * @throws SignatureAttributeException
	 */
	@Override
	public Element getEncoded() throws SignatureAttributeException {
		Document document = null;
		try {
			document = DocumentBuilderFactory.newInstance()
					.newDocumentBuilder().newDocument();
		} catch (ParserConfigurationException e) {
			e.printStackTrace(); // TODO
		}

		Element element = document.createElementNS(
				NamespacePrefixMapperImp.XADES_NS,
				"XAdES:" + this.getIdentifier());

		Element encpasutedTimeStamp = document.createElementNS(
				NamespacePrefixMapperImp.XADES_NS,
				"XAdES:EncapsulatedTimeStamp");

		String base64Value = null;
		try {
			base64Value = new String(Base64.encode(this.contentInfo
					.getEncoded()));
		} catch (IOException e) {
			throw new SignatureAttributeException(e);
		}
		encpasutedTimeStamp.setTextContent(base64Value);
		element.appendChild(encpasutedTimeStamp);
		return element;
	}

	/**
	 * Retorna o nome da tag do atributo
	 * @return Retorna "XAdES:SignatureTimeStamp"
	 */
	protected String getElementName() {
		return "XAdES:SignatureTimeStamp";
	}

	/**
	 * Informa se o atributo é assinado.
	 * @return Indica se o atributo é assinado
	 */
	@Override
	public boolean isSigned() {
		return false;
	}

	/**
	 * Retorna o valor de hash da assinatura
	 * @param hashAlgorithmId O algoritmo a ser utilizado para o cálculo de hash
	 * @return Array de bytes com valor de hash da assinatura
	 * @throws PbadException Exceção em caso de erro no cálculo
	 */
	@Override
	protected byte[] getHashFromSignature(String hashAlgorithmId)
			throws PbadException {
		return this.signatureVerifier.getSignature().getSignatureValueHash(
				AlgorithmIdentifierMapper
						.getAlgorithmNameFromIdentifier(hashAlgorithmId));
	}

	/**
	 * Verifica se o atributo deve ter apenas uma instância na assinatura
	 * @return Indica se o atributo deve ter apenas uma instância na assinatura
	 */
	@Override
	public boolean isUnique() {
		return false;
	}

	/**
	 * Gera o relatório de verificação do carimbo de tempo
	 * @return O relatório criado
	 */
	@Override
	public TimeStampReport getReport() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * Valida o atributo de acordo com suas regras específicas
	 * @throws SignatureAttributeException
	 */
	@Override
	public void validate() throws SignatureAttributeException, PbadException {
		// TODO Auto-generated method stub
		// FIXME - Hierarquia de classes quebrada !!!
	}
}
