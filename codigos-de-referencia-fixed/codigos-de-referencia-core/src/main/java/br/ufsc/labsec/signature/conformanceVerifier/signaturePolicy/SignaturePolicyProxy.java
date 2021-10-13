/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.conformanceVerifier.report.PaReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.Report;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.*;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignerRules.CertInfoReq;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignerRules.CertRefReq;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignerRules.ExternalSignedData;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.exceptions.LpaException;
import org.bouncycastle.util.io.Streams;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.security.auth.x500.X500Principal;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerFactoryConfigurationError;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.Level;

/**
 * Esta classe representa uma Política de Assinatura (PA). Uma PA é composta por três
 * atributos: <br>
 * - o seu resumo criptográfico; <br>
 * - o identificador do método usado para o seu resumo criptográfico; <br>
 * - as informações da política de assinatura. Este contém vários outros
 * atributos. <br>
 *
 * @see <a href="http://www.ietf.org/rfc/rfc3125.txt">RFC 3125</a>
 */
public class SignaturePolicyProxy implements SignaturePolicyInterface {

	/**
	 * Atributo de política de assinatura
	 */
	protected SignaturePolicy signaturePolicy;
	/**
	 * Componente de política de assinatura
	 */
	private SignaturePolicyComponent signaturePolicyComponent;
	/**
	 * Indica se o valor de hash da PA é válido
	 */
	private boolean paHashValid;
	/**
	 * Indica se a referência da PA na LPA é válida
	 */
	private boolean isPaValidOnLpa;
	/**
	 * Indica se a PA foi revogada
	 */
	private boolean isPaRevoked;
	/**
	 * A Lista de Políticas de Assinatura que contém a PA
	 */
    private Lpa lpa;
	/**
	 * Os bytes da assinatura na LPA
	 */
	private byte[] lpaSig;
	/**
	 * O indentificador da política
	 */
    private String oid;

    /**
	 * Construtor. Obtém a PA correspondente a este resumo criptográfico na LPA
	 * @param signaturePolicyHashValue Valor do resumo criptográfico da PA
	 * @param lpaUrl URL da LPA
	 * @throws LpaException Exceção em caso de erro no acesso à LPA
	 */
	public SignaturePolicyProxy(String signaturePolicyHashValue, String lpaUrl) throws LpaException, IOException {
		Lpa lpa = new Lpa();
		if (lpa != null) {
			lpa.readLpa(lpaUrl);
			this.signaturePolicy = lpa.getSignaturePolicy(signaturePolicyHashValue);
		}
	}

	/**
	 * Construtor utilizado quando não tiver acesso a LPA, mas ter o artefato da PA
	 * desejada.
	 * @param signaturePolicyComponent A política de assinatura
	 */
	public SignaturePolicyProxy(SignaturePolicyComponent signaturePolicyComponent) {
		this.signaturePolicyComponent = signaturePolicyComponent;
	}

	/**
	 * Construtor
	 */
	public SignaturePolicyProxy() { }

	/**
	 * Construtor utilizado quando não tiver acesso a LPA, mas ter o acesso a PA
	 * @param signaturePolicyUri URI da política de assinatura
	 * @throws DOMException Exceção em caso de erro no arquivo XML
	 * @throws ParseException Exceção em caso de erro no parsing da data no atributo
	 * @throws CertificateException Exceção em caso de erro na codificação do certificado
	 * @throws IOException Exceção em caso de erro nos bytes do atributo
	 * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
	 * @throws ParserConfigurationException Exceção em caso de erro na configuração do parser
	 * @throws SAXException Exceção em caso de erro na leitura do stream do arquivo da PA
	 */
	public SignaturePolicyProxy(String signaturePolicyUri) throws IOException, DOMException, CertificateException,
			NoSuchAlgorithmException, ParseException, ParserConfigurationException, SAXException {
		FileInputStream inputStream = new FileInputStream(signaturePolicyUri);
		byte[] readedBytes = Streams.readAll(new FileInputStream(signaturePolicyUri));

		byte[] header = new byte[5];
        System.arraycopy(readedBytes, 0, header, 0, 5);
		String headerString = new String(header);
		if (headerString.contains("?xml")) {
			getPaFromXml(inputStream);
		} else {
			getPaFromAsn1(inputStream);
		}
	}

	/**
	 * Busca a PA no arquivo ASN.1 de LPA
	 * @param inputStream Stream que contém o arquivo
	 * @throws ParseException Exceção em caso de erro no parsing da data no atributo
	 * @throws CertificateException Exceção em caso de erro na codificação do certificado
	 * @throws IOException Exceção em caso de erro nos bytes do atributo
	 * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
	 */
	public void getPaFromAsn1(InputStream inputStream)
			throws CertificateException, NoSuchAlgorithmException, IOException, ParseException {
		SignaturePolicy policy = null;
		byte[] encoded = Streams.readAll(inputStream);
		policy = new SignaturePolicy(encoded);
		this.signaturePolicy = policy;
	}

	/**
	 * Busca a PA no arquivo XML de LPA
	 * @param inputStream Stream que contém o arquivo
	 * @throws DOMException Exceção em caso de erro no arquivo XML
	 * @throws ParseException Exceção em caso de erro no parsing da data no atributo
	 * @throws CertificateException Exceção em caso de erro na codificação do certificado
	 * @throws IOException Exceção em caso de erro nos bytes do atributo
	 * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
	 * @throws ParserConfigurationException Exceção em caso de erro na configuração do parser
	 * @throws SAXException Exceção em caso de erro na leitura do stream
	 */
	private void getPaFromXml(InputStream inputStream) throws DOMException, CertificateException,
			NoSuchAlgorithmException, ParseException, IOException, ParserConfigurationException, SAXException {
		SignaturePolicy policy = null;
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder builder;
		builder = factory.newDocumentBuilder();
		Document document = builder.parse(inputStream);
		policy = new SignaturePolicy(document);
		this.signaturePolicy = policy;
	}

	/**
	 * Obtém os identificadores dos atributos assinados obrigatórios do
	 * assinante.
	 * @return Lista com os identificadores dos atributos.
	 */
	public List<String> getMandatedSignedAttributeList() {
		ArrayList<String> mandatedSignedAttributeList = new ArrayList<String>();
		if (this.signaturePolicy != null) {
            Collections.addAll(mandatedSignedAttributeList, this.signaturePolicy.getSignPolicyInfo()
                    .getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules()
                    .getMandatedSignedAttr());
		}
		return mandatedSignedAttributeList;
	}

	/**
	 * Indica se a PA é XML
	 * @return Indica se a Política de Assinatura é XML.
	 */
	public boolean isXml() {
		if (this.signaturePolicy == null) {
			return false;
		}
		return this.signaturePolicy.hasTransforms();
	}

	/**
	 * Verifica se há regras adicionais do assinante na política
	 * @param oid O identificador da regra
	 * @return Indica se a regra indicada está presente na PA
	 */
	public boolean signerRulesExtensionExists(String oid) {
		SignerRules signerRules = this.signaturePolicy.getSignPolicyInfo()
				.getSignatureValidationPolicy().getCommonRules()
				.getSignerAndVeriferRules().getSignerRules();

		SignaturePolicyExtension[] sigPolExtensions = signerRules.getSignPolExtensions();

		for(SignaturePolicyExtension sigPol : sigPolExtensions){
			if(sigPol.getExtnID().equals(oid)){
				return true;
			}
		}
		return false;
	}

	/**
	 * Verifica se há regras adicionais do verificador na política
	 * @param oid O identificador da regra
	 * @return Indica se a regra indicada está presente na PA
	 */
	public boolean verifierRulesExtensionExists(String oid) {
		if (this.signaturePolicy != null) {
			VerifierRules verifierRules = this.signaturePolicy.getSignPolicyInfo()
					.getSignatureValidationPolicy().getCommonRules()
					.getSignerAndVeriferRules().getVerifierRules();

			SignaturePolicyExtension[] sigPolExtensions = verifierRules.getSignPolExtensions();

			for(SignaturePolicyExtension sigPol : sigPolExtensions){
				if(sigPol.getExtnID().equals(oid)){
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Retorna a extensão de assinatura brExtMandatedPdfSigDicEntries
	 * @return O valor da extensão
	 */
	public BrExtMandatedPdfSigDicEntries signerRulesGetBrExtMandatedPdfSigDicEntries() {
		SignerRules signerRules = this.signaturePolicy.getSignPolicyInfo()
				.getSignatureValidationPolicy().getCommonRules()
				.getSignerAndVeriferRules().getSignerRules();

        return signerRules.getBrExtMandatedPdfSigDicEntries();
	}

	public BrExtDss signerRulesGetBrExtDss() {
		SignerRules signerRules = this.signaturePolicy.getSignPolicyInfo()
				.getSignatureValidationPolicy().getCommonRules()
				.getSignerAndVeriferRules().getSignerRules();
		return signerRules.getBrExtDss();
	}

	/**
	 * Retorna a extensão de assinatura brExtMandatedPdfSigDicEntries
	 * @return O valor da extensão
	 */
	public BrExtDss verifierRulesGetBrExtDss() {
		VerifierRules verifierRules = this.signaturePolicy.getSignPolicyInfo()
				.getSignatureValidationPolicy().getCommonRules()
				.getSignerAndVeriferRules().getVerifierRules();

        return verifierRules.getBrExtDss();
	}

	/**
	 * Informa se os dados assinados devem ser externos ou internos à
	 * assinatura, ou se ambos os modos são permitidos.
	 * @return Indica o modo dos dados assinados
	 */
	public ExternalSignedData getExternalSignedData() {
		if (this.signaturePolicy != null) {
			return this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
					.getSignerAndVeriferRules().getSignerRules().getExternalSignedData();
		} else {
			return null;
		}
	}

	/**
	 * Retorna o período em que é permitido usar esta Política de Assinatura.
	 * @return Intervalo de tempo em que a assinatura deve ser usada.
	 */
	public SigningPeriod getSigningPeriod() {
		if (this.signaturePolicy != null) {
			return this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getSigningPeriod();
		} else {
			return null;
		}
	}

	/**
	 * Retorna o primeiro tamanho mínimo de chaves, do signatário, aceitável pela PA.
	 * @return tamanho da chave do signatário em bits.
	 */
	public int getMinKeyLength() {
		if (this.signaturePolicy != null) {
			return this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
					.getAlgorithmConstraintSet().getSignerAlgorithmConstraints()[0].getMinKeyLength();
		} else {
			return 0;
		}
	}

	/**
	 * Retorna todos os tamanho mínimo de chaves, do signatário, aceitável pela PA.
	 * @return Os tamanhos da chave do signatário em bits.
	 */
	public int[] getMinKeyLengthSet() {
		if (this.signaturePolicy != null) {
			AlgAndLength[] algLenghtSet = this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
					.getAlgorithmConstraintSet().getSignerAlgorithmConstraints();
			int[] lenghts = new int[algLenghtSet.length];
			for (int i = 0; i < algLenghtSet.length; i++) {
				lenghts[i] = algLenghtSet[i].getMinKeyLength();
			}
			return lenghts;
		} else {
			return new int[]{0};
		}
	}

	/**
	 * Retorna o conjunto de âncoras de confiança da PA
	 * @return O conjunto de âncoras de confiança da PA
	 */
	public Set<TrustAnchor> getSigningTrustAnchors() {
		Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
		TrustAnchor trustAnchor;
		if (this.signaturePolicy == null) {
			return this.signaturePolicyComponent.trustAnchorInterface.getTrustAnchorSet();
		}

		for (CertificateTrustPoint trustPoint : this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy()
				.getCommonRules().getSigningCertTrustCondition().getSignerTrustTrees()) {
			trustAnchor = new TrustAnchor((X509Certificate) trustPoint.getTrustPoint(), null);
			trustAnchors.add(trustAnchor);
		}

		return trustAnchors;
	}

	/**
	 * Retorna o conjunto de âncoras de confiança para carimbos do tempo da PA.
	 * @return O conjunto de âncoras de confiança
	 */
	public Set<TrustAnchor> getTimeStampTrustAnchors() {
		Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();


		if (this.signaturePolicy == null){
			return this.signaturePolicyComponent.trustAnchorInterface.getTrustAnchorSet();
		}

		CommonRules commomRules = this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy()
				.getCommonRules();
		TimeStampTrustCondition timeStampTrustConditions = commomRules.getTimeStampTrustCondition();
		if (timeStampTrustConditions.getTtsCertificateTrustTrees() != null) {
			CertificateTrustPoint[] trustTrees = timeStampTrustConditions.getTtsCertificateTrustTrees();
			TrustAnchor trustAnchor;
			for (CertificateTrustPoint trustPoint : trustTrees) {
				trustAnchor = new TrustAnchor((X509Certificate) trustPoint.getTrustPoint(), null);
				trustAnchors.add(trustAnchor);
			}
		} else {
			trustAnchors = this.getSigningTrustAnchors();
		}
		return trustAnchors;
	}

	/**
	 * A partir do nome da última Autoridade Certificadora do caminho de
	 * certificação do signatário, é obtido o atributo
	 * {@link CertificateTrustPoint}, que reune o certificado auto-assinado da
	 * AC (Autoridade Certificadora) usada para começar (ou terminar) o
	 * processamento do caminho de certificação do signatário, e as condições
	 * iniciais para a validação do caminho de certificação.
	 * @param issuerX500Principal Nome do emissor da última AC do caminho de certificação.
	 * @return O atributo <code> certificateTrustPoint </code>.
	 */
	public CertificateTrustPoint getTrustPoint(X500Principal issuerX500Principal) {
		if (this.signaturePolicy != null) {
			CertificateTrustPoint[] trustTrees = this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy()
					.getCommonRules().getSigningCertTrustCondition().getSignerTrustTrees();
			int i = 0;
			int trustTreeIndex = -1;
			while (trustTreeIndex == -1 && i < trustTrees.length) {
				X509Certificate trustAnchor = (X509Certificate) trustTrees[i].getTrustPoint();
				if (issuerX500Principal.equals(trustAnchor.getSubjectX500Principal())) {
					trustTreeIndex = i;
				}
				i++;
			}
			return trustTrees[i - 1];
		}
		return null;
	}

	/**
	 * A partir do nome da última Autoridade Certificadora do caminho de
	 * certificação do signatário, é obtido o atributo
	 * {@link CertificateTrustPoint}, que reune as condições de confiança
	 * necessárias para o processamento do caminho de certificação usado para
	 * autenticar a ACT (Autoridade de Carimbo do Tempo) e restrições no nome da
	 * ACT.
	 * @param issuerX500Principal O nome do emissor da última AC do caminho de certificação.
	 * @return O atributo <code> certificateTrustPoint </code>
	 */
	public CertificateTrustPoint getTimeStampTrustPoint(X500Principal issuerX500Principal) {
		CertificateTrustPoint[] trustTrees = this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy()
				.getCommonRules().getTimeStampTrustCondition().getTtsCertificateTrustTrees();
		int i = 0;
		int trustTreeIndex = -1;
		while (trustTreeIndex == -1 && i < trustTrees.length) {
			X509Certificate trustAnchor = (X509Certificate) trustTrees[i].getTrustPoint();
			if (issuerX500Principal.equals(trustAnchor.getSubjectX500Principal())) {
				trustTreeIndex = i;
			}
			i++;
		}
		return trustTrees[i - 1];
	}

	/**
	 * Retorna o conjunto de pontos de confiança do carimbo de tempo
	 * @return O onjunto de pontos de confiança
	 */
	@Override
	public Set<CertificateTrustPoint> getTimeStampTrustPoints() {

		if (this.signaturePolicy == null) {
			return null;
		}

		// FIXME getTimeStampTrustCondition null

		TimeStampTrustCondition timeStampTrustCondition = this.signaturePolicy.getSignPolicyInfo()
				.getSignatureValidationPolicy().getCommonRules().getTimeStampTrustCondition();

		CertificateTrustPoint[] trustTrees = null;

		if (timeStampTrustCondition == null || timeStampTrustCondition.getTtsCertificateTrustTrees() == null) {
			trustTrees = this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
					.getSigningCertTrustCondition().getSignerTrustTrees();
		} else {
			trustTrees = this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
					.getTimeStampTrustCondition().getTtsCertificateTrustTrees();
		}

		Set<CertificateTrustPoint> trustPointsSet = new HashSet<CertificateTrustPoint>();
        Collections.addAll(trustPointsSet, trustTrees);

		return trustPointsSet;
	}

	/**
	 * Retorna os requisitos de revogação para certificados
	 * @return Os requisitos de revogação para certificados
	 */
	public CertRevReq getTimeStampRevocationReqs() {

		if (this.signaturePolicy == null){
			return new CertRevReq(RevReq.EnuRevReq.EITHER_CHECK, RevReq.EnuRevReq.EITHER_CHECK);
		}

		TimeStampTrustCondition timeStampTrustCondition = this.signaturePolicy.getSignPolicyInfo()
				.getSignatureValidationPolicy().getCommonRules().getTimeStampTrustCondition();

		CertRevReq revReq = null;

		if (timeStampTrustCondition == null) {
			revReq = this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
					.getSigningCertTrustCondition().getSignerRevReq();
		} else {
			revReq = this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
					.getTimeStampTrustCondition().getTtsRevReq();
		}

		return revReq;
	}

	/**
	 * Retorna o primeiro identificador do algoritmo de assinatura especificado por esta
	 * Política de Assinatura.
	 * @return O identificador do algoritmo
	 */
	public String getSignatureAlgorithmIdentifier() {
		if (this.signaturePolicy != null) {
			return this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
					.getAlgorithmConstraintSet().getSignerAlgorithmConstraints()[0].getAlgID();
		} else {
			return "";
		}
	}

	public String[] getSignatureAlgorithmIdentifiers() {
		if (this.signaturePolicy != null) {
			AlgAndLength[] constraints = this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
					.getAlgorithmConstraintSet().getSignerAlgorithmConstraints();
			String[] identifiers = new String[constraints.length];
			for (int i = 0; i < constraints.length; i++) {
				identifiers[i] = constraints[i].getAlgID();
			}
			return identifiers;
		}
		return new String[0];
	}

	/**
	 * Retorna os identificadores de algoritmos de assinatura especificados por esta
	 * Política de Assinatura.
	 * @return Lista de identificadores
	 */
	public String[] getSignatureAlgorithmIdentifierSet() {
		if (this.signaturePolicy != null) {
			AlgAndLength[] algLenghtSet = this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
					.getAlgorithmConstraintSet().getSignerAlgorithmConstraints();
			String[] ids = new String[algLenghtSet.length];
			for (int i = 0; i < algLenghtSet.length; i++) {
				ids[i] = algLenghtSet[i].getAlgID();
			}
			return ids;
		} else {
			return new String[]{""};
		}
	}

	/**
	 * Retorna qual será a referência obrigatória do certificado usada nesta
	 * Política de Assinatura. Esta informação é guardada pelo atributo
	 * <code> mandatedCertificateRef </code>, que será retornado. A referência
	 * pode ser somente o certificado do signatário (<code> signerOnly </code>),
	 * ou o caminho de certificação  completo(<code> fullPath </code>).
	 * @return A referência obrigatória do certificado
	 */
	public CertRefReq getSigningCertRefReq() {
		if (this.signaturePolicy == null){
			return null;
		}
		return this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
				.getSignerAndVeriferRules().getSignerRules().getMandatedCertificateRef();
	}

	/**
	 * Retorna o atributo <code> signerRevReq </code>, que representa o mínimo
	 * de requerimentos de revogação que devem ser checados.
	 * @return O mínimo de requerimentos de revogação a serem verificados
	 */
	public CertRevReq getSignerRevocationReqs() {
		if (this.signaturePolicy != null) {
			return this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
					.getSigningCertTrustCondition().getSignerRevReq();
		} else {
			return new CertRevReq(RevReq.EnuRevReq.EITHER_CHECK, RevReq.EnuRevReq.EITHER_CHECK);
		}
	}

	/**
	 * Retorna o identificador do algoritmo de resumo criptográfico especificado
	 * pela Política de Assinatura. Se for XAdES, o retorno será uma URL, e se
	 * for CAdES, será um OID.
	 * @return O identificador do algoritmo de resumo criptográfico.
	 */
	public String getHashAlgorithmId() {
		return SignatureAlgorithmToDigestFunctionMapper
				.getAlgorithmNameFromIdentifier(this.getSignatureAlgorithmIdentifier());
	}

	@Override
	public String[] getHashAlgorithmIdSet() {
		return this.getSignatureAlgorithmIdentifiers();
	}

	/**
	 * Retorna o resumo criptográfico da Política de Assinatura.
	 * @return Valor do resumo criptográfico da Política de Assinatura.
	 */
	public byte[] getSignPolicyHash() {
		if (this.signaturePolicy != null) {
			return this.signaturePolicy.getSignPolicyHash();
		}
		return new byte[0];
	}

	/**
	 * Retorna o identificador da Política de Assinatura.
	 * @return O identificador da Política de Assinatura
	 */
	public String getSignaturePolicyIdentifier() {
		return this.signaturePolicy.getSignPolicyInfo().getSignPolicyIdentifier();
	}

	/**
	 * Retorna as regras de comprometimento do signatário.
	 * @return As regras de comprometimento
	 */
	public CommitmentRule[] getCommitmentRules() {
		SignaturePolicyInfo signaturePolicyInfo = this.signaturePolicy.getSignPolicyInfo();
		SignatureValidationPolicy signatureValidationPolicy = signaturePolicyInfo.getSignatureValidationPolicy();
		return signatureValidationPolicy.getCommitmentRules();
	}

	/**
	 * Inicializa a política com valores padrão
	 */
	@Override
	public void setDefaultPolicy() {
		this.oid = "";

		this.lpa = null;
		try {
			lpa = new Lpa();
			lpa.getPolicyOids().add("");

			this.signaturePolicy = null;
			this.isPaValidOnLpa = false;

			this.paHashValid = false;
			this.isPaRevoked = true;
		} catch (TransformerFactoryConfigurationError e) {
			Application.logger.log(Level.SEVERE, e.getMessage());
		}
	}

	/**
	 * Atualiza a política com as informações dadas.
	 * @param policyIdentifier Identificador da política
	 * @param lpaStream Stream da lista de políticas de assinatura
	 * @param lpaSigStream Stream da assinatura da política
	 * @param policyStream stream da política
	 * @param policyType Tipo da política
	 */
	public void setActualPolicy(String policyIdentifier, InputStream lpaStream, InputStream lpaSigStream, InputStream policyStream, AdESType policyType) {
		this.oid = policyIdentifier;
		try {
			this.lpa = new Lpa();
			if (lpaSigStream != null) {
				this.lpa.readLpa(lpaStream, lpaSigStream);
			} else {
				this.lpa.readLpa(lpaStream);
			}

			if (policyType == AdESType.XAdES) {
				getPaFromXml(policyStream);
			} else {
				getPaFromAsn1(policyStream);
			}
			if (!this.signaturePolicy.getSignPolicyInfo().getSignPolicyIdentifier().equals(policyIdentifier)) {
				throw new LpaException("OID da política não é o mesmo da utilizada na assinatura");
			}
			lpa.setLastPolicy(this.signaturePolicy);
			this.isPaValidOnLpa = lpa.isPaValid();

			this.paHashValid = this.signaturePolicy.validateHash();
			this.isPaRevoked = this.lpa.isRevoked(this.signaturePolicy.getSignPolicyInfo().getSignPolicyIdentifier());

		} catch (IOException | ParserConfigurationException | SAXException | NoSuchAlgorithmException
				| CertificateException | ParseException | LpaException e) {
			Application.logger.log(Level.SEVERE, e.getMessage());
		}
	}

	/**
	 * Atualiza a política com as informações dadas
	 * @param signaturePolicyIdentifier Identificador da política
	 * @param signaturePolicyUri URI da política
	 * @param policyType Tipo da política
	 */
	@Override
	public void setActualPolicy(String signaturePolicyIdentifier, String signaturePolicyUri, AdESType policyType) {
	    String lpaUrl = getURL(policyType);
	    String lpaSigUrl = getSigURL(policyType);

		this.oid = signaturePolicyIdentifier;
	    if (signaturePolicyIdentifier.startsWith("urn")) {
			this.oid = this.oid.substring(8); // remove "urn:oid:"
		}

		this.lpa = null;
		try {
			lpa = new Lpa();
			if (lpaSigUrl != null) {
				lpa.readLpa(lpaUrl, lpaSigUrl);
			} else {
				lpa.readLpa(lpaUrl);
			}

			String policyOid = this.lpa.getPolicyNameToOid().get(signaturePolicyIdentifier);

			this.signaturePolicy = null;
			if (policyOid != null) {
				this.signaturePolicy = lpa.getSignaturePolicy(policyOid);
			} else {
				this.signaturePolicy = lpa.getSignaturePolicy(signaturePolicyIdentifier);
			}
			this.isPaValidOnLpa = lpa.isPaValid();

			this.paHashValid = this.signaturePolicy.validateHash();
			this.isPaRevoked = lpa.isRevoked(this.oid);

		} catch (NoSuchAlgorithmException | IOException | TransformerFactoryConfigurationError | LpaException e) {
			Application.logger.log(Level.SEVERE, e.getMessage());
		}
	}

	/**
	 * Retorna o conjunto de pontos de confiança
	 * @return O conjunto de pontos de confiança
	 */
	@Override
	public Set<CertificateTrustPoint> getTrustPoints() {
		if (this.signaturePolicy == null) {
			return null;
		}

		SignatureValidationPolicy signatureValidationPolicy = this.signaturePolicy.getSignPolicyInfo()
				.getSignatureValidationPolicy();
		CertificateTrustPoint[] signerTrustTrees = signatureValidationPolicy.getCommonRules()
				.getSigningCertTrustCondition().getSignerTrustTrees();
		Set<CertificateTrustPoint> trustPointsSet = new HashSet<CertificateTrustPoint>();
        Collections.addAll(trustPointsSet, signerTrustTrees);

		return trustPointsSet;
	}

	/**
	 * Retorna o relatório da verificação da política de assinatura
	 * @return O relatório de verificação
	 */
	@Override
	public PaReport getReport() {
		PaReport report = new PaReport();
		if (this.signaturePolicy != null) {
			int policyIndex = 0;
			if (this.isXml()) {
				policyIndex = this.lpa.getPolicyOids()
						.indexOf(this.signaturePolicy.getSignPolicyInfo().getSignPolicyIdentifier().substring(8)); // remove
																													// the
																													// urn:oid:
			} else {
				policyIndex = this.lpa.getPolicyOids()
						.indexOf(this.signaturePolicy.getSignPolicyInfo().getSignPolicyIdentifier());
			}
			String policyName = this.lpa.getPoliciesNames().get(policyIndex);
			report.setOid(policyName + " (" + this.signaturePolicy.getSignPolicyInfo().getSignPolicyIdentifier() + ")");
			// TODO - Não temos cache ainda
			report.setPaOnline(true);
			SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss z");
			report.setPaPeriod("de "
					+ formatter.format(this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy()
							.getSigningPeriod().getNotBefore())
					+ " até " + formatter.format(this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy()
							.getSigningPeriod().getNotAfter()));
			report.setValidPa(this.isPaHashValid());
			report.setValidOnLpa(this.isPaValidOnLpa());
			report.setPaRevoked(this.isPaRevoked());
		} else {
			report.setOid("O OID " + this.oid
					+ " utilizado na assinatura não é válido.");

			String paType = getPaType(this.oid);
			String signatureType = getPaType(this.lpa.getPolicyOids().get(0));
			String paError;
			if (!paType.equals("") && !paType.equals(signatureType)) {
				paError = "O OID corresponde a uma Política de Assinatura ICP-Brasil " + paType + " e está sendo utilizado em uma assinatura do tipo " + signatureType + ".";
			} else {
				paError = "O OID utilizado não corresponde a nenhuma Política de Assinatura ICP-Brasil do tipo " + signatureType + ".";
			}
			report.setPaError(paError);
		}
		return report;
	}

	/**
	 * Indica o tipo de assinatura que a PA se refere
	 * @param oid O indentificador da política
	 * @return O tipo da PA (CAdES, XAdES ou PAdES)
	 */
	private String getPaType(String oid) {
		String type = "";
		if (oid != "") {
			if (oid.startsWith("2.16.76.1.7.1.11")) {
				type = "PAdES";
			} else if (oid.startsWith("2.16.76.1.7.1.6")) {
				type = "XAdES";
			} else if (oid.startsWith("2.16.76.1.7.1.1")) {
				type = "CAdES";
			}
		}
		return type;
	}

	/**
	 * Informa se a referência da PA na LPA é válida
	 * @return Indica se a referência da PA na LPA é válida
	 */
	private boolean isPaValidOnLpa() {
		return this.isPaValidOnLpa;
	}

	/**
	 * Informa se o valor de hash da PA é válido
	 * @return Indica se o hash é válido
	 */
	private boolean isPaHashValid() {
		return this.paHashValid;
	}

	/**
	 * Informa se a política foi revogada
	 * @return Indica se a política foi revogada
	 */
	private boolean isPaRevoked() {
		return this.isPaRevoked;
	}

	/**
	 * Atualiza o relatório com informações da LPA que contém a PA
	 * @param report Relatório de verificação
	 * @param policyType O tipo de política da PA
	 */
	@Override
	public void getLpaReport(Report report, AdESType policyType) {
		LpaValidator lpaValidator = new LpaValidator(this.lpa, report, signaturePolicyComponent);
		lpaValidator.validate(policyType);
		lpaValidator.verifyLpaExpirationDate(report);
	}

	/**
	 * Retorna o identificador da política de assinatura
	 * @return O identificador da política
	 */
	@Override
	public String getPolicyId() {
		return this.signaturePolicy.getSignPolicyInfo().getSignPolicyIdentifier();
	}

	/**
	 * Retorna a URL da LPA
	 * @param type O tipo da política
	 * @return A URL da LPA
	 */
	@Override
	public String getURL(AdESType type) {
		String lpaUrl = null;
		Application application = this.signaturePolicyComponent.getApplication();
		switch (type) {
			case XAdES:
				lpaUrl = application.getComponentParam(signaturePolicyComponent, "lpaUrlXml");
				break;
			case CAdES:
				lpaUrl = application.getComponentParam(signaturePolicyComponent, "lpaUrlAsn1CAdES");
				break;
			case PAdES:
				lpaUrl = application.getComponentParam(signaturePolicyComponent, "lpaUrlAsn1PAdES");
		}

		return lpaUrl;
	}

	/**
	 * Retorna a URL que contém o arquivo de assinatura da LPA.
	 * Utilizado apenas em assinaturas PAdES, na construção do dicionário DSS.
	 * @param type o tipo da assinatura
	 * @return A URL do arquivo de assinatura da LPA caso o tipo da assinatura seja PAdES,
	 * 		ou nulo caso o tipo da assinatura seja CAdES ou XAdES
	 */
	@Override
	public String getSigURL(AdESType type) {
		String lpaUrl = null;
		Application application = this.signaturePolicyComponent.getApplication();
		if (type == AdESType.PAdES) {
				lpaUrl = application.getComponentParam(signaturePolicyComponent, "lpaUrlAsn1SignaturePAdES");
		}
		return lpaUrl;
	}

	/**
	 * Retorna a informação obrigatória de certificado
	 * @return A informação obrigatória de certificado
	 */
	@Override
	public CertInfoReq getMandatedCertificateInfo() {
		if (this.signaturePolicy != null) {
			return this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
					.getSignerAndVeriferRules().getSignerRules().getMandatedCertificateInfo();
		} else {
			return null;
		}
	}

	/**
	 * Obtém os identificadores dos atributos não assinados obrigatórios do
	 * verificador.
	 * @return Lista com os identificadores dos atributos.
	 */
	public List<String> getMandatedUnsignedVerifierAttributeList() {
		ArrayList<String> mandatedUnsignedAttrs = new ArrayList<String>();
		if (this.signaturePolicy != null) {
            mandatedUnsignedAttrs.addAll(Arrays.asList(this.signaturePolicy.getSignPolicyInfo()
                    .getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getVerifierRules()
                    .getMandatedUnsignedAttr()));
		}
		return mandatedUnsignedAttrs;
	}

	/**
	 * Retorna a lista de políticas na LPA
	 * @param type O tipo da política
	 * @return Lista com os OIDs das políticas contidas na LPA
	 */
	@Override
	public List<String> getPoliciesAvaiable(AdESType type) {

		String lpaUrl = getURL(type);

		this.lpa = null;
		this.lpa = new Lpa();
		try {
			this.lpa.readLpa(lpaUrl);

		} catch (LpaException | IOException e) {
			e.printStackTrace();
		}

		return new ArrayList<String>(this.lpa.getPolicyNameToOid().keySet());
	}

	/**
	 * Atribue a LPA
	 * @param lpa Os bytes da LPA
	 */
    public void setLpa(byte[] lpa) {
        this.lpa.setLpa(lpa);
    }

	/**
	 * Retorna a PA
	 * @return A política de assinatura
	 */
	public SignaturePolicy getSignaturePolicy() {
		return signaturePolicy;
	}

	/**
	 * Obtém os identificadores dos atributos não assinados obrigatórios do
	 * assinador
	 * @return Lista com os identificadores dos atributos
	 */
	public List<String> getMandatedUnsignedSignerAttributeList() {
		ArrayList<String> mandatedUnsignedAttrs = new ArrayList<String>();
		if (this.signaturePolicy != null) {
            Collections.addAll(mandatedUnsignedAttrs, this.signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy()
                    .getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedUnsignedAttr());
		}
		return mandatedUnsignedAttrs;
	}

	/**
	 * Retorna a extensão de assinatura brExtMandatedDocTSEntries
	 * @return O valor da extensão
	 */
	public BrExtMandatedDocTSEntries signerRulesGetBrExtMandatedDocTSEntries() {
		SignerRules signerRules = this.signaturePolicy.getSignPolicyInfo()
				.getSignatureValidationPolicy().getCommonRules()
				.getSignerAndVeriferRules().getSignerRules();

        return signerRules.getBrExtMandatedDocTSEntries();
	}

	/**
	 * Retorna a extensão de assinatura brExtMandatedDocTSEntries
	 * @return O valor da extensão
	 */
    public BrExtMandatedDocTSEntries verifierRulesGetBrExtMandatedDocTSEntries() {
        VerifierRules verifierRules = this.signaturePolicy.getSignPolicyInfo()
                .getSignatureValidationPolicy().getCommonRules()
                .getSignerAndVeriferRules().getVerifierRules();

        return verifierRules.getBrExtMandatedDocTSEntries();
    }

    public Lpa getLpa() {
		return lpa;
	}
}
