/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CRLSelector;
import java.security.cert.CertPath;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.util.encoders.Base64;

import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdContentType;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.CertRevReq;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.RevReq;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;


/**
 * Este atributo deve conter apenas todas LCRs ou respostas OCSP do caminho de
 * certificação do assinante.
 * <p>
 * Somente uma instância deste atributo é permitida na assinatura.
 * <p>
 * 
 * Oid e esquema do atributo id-aa-ets-revocationRefs retirado do documento ETSI
 * TS 101 733 V1.8.1:
 * <p>
 * 
 * <pre>
 * id-aa-ets-revocationRefs OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 22}
 * 
 * CompleteRevocationRefs ::= SEQUENCE OF CrlOcspRef
 * 
 * </pre>
 */
public class IdAaEtsRevocationRefs implements SignatureAttribute, CRLSelector {

	public static final String IDENTIFIER = PKCSObjectIdentifiers.id_aa_ets_revocationRefs
			.getId();
	/**
	 * Lista de identificadores das CRLS
	 */
	private List<ASN1Encodable> crlIds;
	/**
	 * Lista de identificadores das respostas OCSP
	 */
	private List<ASN1Encodable> ocspIds;
	/**
	 * Conjunto de hashes de CRLs
	 */
	private Set<String> crlHashsSet;
	/**
	 * Conjunto de IDs das respostas OCSP
	 */
	private Set<String> ocspIdsSet;
	/**
	 * Algoritmo de cálculo de hash
	 */
	private String algorithm;
	/**
	 * Objeto de verificador
	 */
	private AbstractVerifier signatureVerifier;

	/**
	 * Deve-se utilizar este construtor no momento de validação do atributo. O
	 * parâmetro <code> index </code> deve ser usado no caso em que há mais de
	 * um atributo do mesmo tipo. Caso contrário, ele deve ser zero.
	 * @param signatureVerifier Usado para criar e verificar o atributo
	 * @param index Índice usado para selecionar o atributo
	 * @throws SignatureAttributeException
	 */
	public IdAaEtsRevocationRefs(AbstractVerifier signatureVerifier,
			Integer index) throws SignatureAttributeException {
		this.signatureVerifier = signatureVerifier;
		CadesSignature signature = this.signatureVerifier.getSignature();
		Attribute genericEncoding = signature.getEncodedAttribute(
				this.getIdentifier(), index);
		this.decode(genericEncoding);
	}

	/**
	 * Cria um atributo que irá referenciar as LCRs passadas na lista. Na
	 * referência será usado um algoritmo de hash o identificador do mesmo deve
	 * ser passado para <code>digestAlgorithm</code>
	 * @param crls A lista de CRLS
	 * @param digestAlgorithm O algoritmo de hash
	 * @throws SignatureAttributeException
	 */
	public IdAaEtsRevocationRefs(List<X509CRL> crls, String digestAlgorithm)
			throws SignatureAttributeException {
		this.makeCrlIdentifiers(crls, digestAlgorithm);
		this.makeCrlIdSet();
		this.algorithm = digestAlgorithm;
	}

	/**
	 * Cria um atributo que irá referenciar as respostas OCSP passadas na lista.
	 * Na referência será usado um algoritmo de hash o identificador do mesmo
	 * deve ser passado para <code>digestAlgorithm</code>
	 * @param digestAlgorithm O algoritmo de hash
	 * @param basicOCSPResponses A lista de respostas OCSP
	 * @throws SignatureAttributeException
	 */
	public IdAaEtsRevocationRefs(String digestAlgorithm,
			List<BasicOCSPResponse> basicOCSPResponses)
			throws SignatureAttributeException {
		this.makeOcspIdentifiers(basicOCSPResponses, digestAlgorithm);
		this.makeOcspIdSet();
		this.algorithm = digestAlgorithm;
	}

	/**
	 * Cria um atributo que irá referenciar as respostas OCSP e LCRs passadas na
	 * lista. Na referência será usado um algoritmo de hash o identificador do
	 * mesmo deve ser passado para <code>digestAlgorithm</code>.
	 * @param crls A lista de CRLs
	 * @param basicOCSPResponses A lista de respostas OCSP
	 * @param digestAlgorithm O algoritmo de hash
	 * @throws SignatureAttributeException
	 */
	public IdAaEtsRevocationRefs(List<X509CRL> crls,
			List<BasicOCSPResponse> basicOCSPResponses, String digestAlgorithm)
			throws SignatureAttributeException {
		this.makeCrlIdentifiers(crls, digestAlgorithm);
		this.makeOcspIdentifiers(basicOCSPResponses, digestAlgorithm);
		this.makeCrlIdSet();
		this.makeOcspIdSet();
		this.algorithm = digestAlgorithm;
	}

	/**
	 * Permite decodificar um atributo já existente para que esse possa ser
	 * usado como {@link CRLSelector} ou então para selecionar as respostas
	 * OCSP.
	 * @param genericEncoding O atributo codificado
	 * @throws EncodingException
	 * @throws SignatureAttributeException
	 */
	public IdAaEtsRevocationRefs(Attribute genericEncoding)
			throws EncodingException, SignatureAttributeException {
		this.decode(genericEncoding);
	}

	/**
	 * Construtor
	 */
	private IdAaEtsRevocationRefs() {
	}

	/**
	 * Constrói um objeto {@link IdAaEtsRevocationRefs}
	 * @param genericEncoding O atributo codificado
	 */
	@SuppressWarnings("rawtypes")
	private void decode(Attribute genericEncoding)
			throws SignatureAttributeException {
		Attribute revocationRefsAttribute;
		revocationRefsAttribute = genericEncoding;
		ASN1Set revocationRefsValue = revocationRefsAttribute.getAttrValues();
		ASN1Sequence revocationRefsSequence = (ASN1Sequence) revocationRefsValue.getObjectAt(0);
		Enumeration revocationRefs = revocationRefsSequence.getObjects();
		while (revocationRefs.hasMoreElements()) {
			ASN1Sequence crlOcspRefs = (ASN1Sequence) revocationRefs.nextElement();
			Enumeration refs = crlOcspRefs.getObjects();
			while (refs.hasMoreElements()) {
				ASN1TaggedObject ref = (ASN1TaggedObject) refs.nextElement();
				switch (ref.getTagNo()) {
				case 0:
					this.decodeCrlListId(ref.getObject());
					break;
				case 1:
					this.decodeOcspListId(ref.getObject());
					break;
				case 2:
					throw new SignatureAttributeException(
							"Identificador de dados de validação desconhecido");
				}
			}
		}
		this.makeCrlIdSet();
		this.makeOcspIdSet();
	}

	/**
	 * Preenche a lista de identificadores de CRL com os dados presentes
	 * no objeto ASN.1 dado
	 * @param crlListId O objeto ASN.1 que contém as informações de CRL
	 */
	private void decodeCrlListId(ASN1Object crlListId) {
		if(this.crlIds == null)
			this.crlIds = new ArrayList<ASN1Encodable>();
		if(this.crlHashsSet == null)
			this.crlHashsSet = new HashSet<String>();
		ASN1Sequence crlListIdSequence = (ASN1Sequence) crlListId;
		@SuppressWarnings("rawtypes")
		Enumeration crlListIds = crlListIdSequence.getObjects();
		while (crlListIds.hasMoreElements()) {
			ASN1Sequence crlsSequence = (ASN1Sequence) crlListIds.nextElement();
			for (int i = 0; i < crlsSequence.size(); i++) {
				ASN1Sequence crlValidateId = (ASN1Sequence) crlsSequence.getObjectAt(i);
				this.decodeCrlValidateId(crlValidateId);
			}
		}
	}

	/**
	 * Calcula o hash da entrada 'crlValidateId' e adiciona no conjunto de hashes
	 * de CRLs
	 * @param crlValidateId A entrada 'crlValidateId' de uma CRL
	 */
	private void decodeCrlValidateId(ASN1Sequence crlValidateId) {
		this.crlIds.add(crlValidateId);
		byte[] crlHash = this.getCrlHashFromValidateId(crlValidateId);
		this.crlHashsSet.add(new String(Base64.encode(crlHash)));
	}

	/**
	 * Calcula o hash das respostas OCSP e adiciona no conjunto de hashes
	 * de resposta OCSP
	 * @param ocspListId A resposta OCSP
	 */
	private void decodeOcspListId(ASN1Object ocspListId) {
		this.ocspIds = new ArrayList<ASN1Encodable>();
		this.ocspIdsSet = new HashSet<String>();
		ASN1Sequence ocspListIdSequence = (ASN1Sequence) ocspListId;
		@SuppressWarnings("rawtypes")
		Enumeration ocspListIds = ocspListIdSequence.getObjects();
		while (ocspListIds.hasMoreElements()) {
			DERSequence object = (DERSequence) ocspListIds.nextElement();
			this.decodeOcspResponsesId(object);
		}
	}

	/**
	 * Calcula o hash de uma resposta OCSP e adiciona no conjunto de hashes
	 * de resposta OCSP
	 * @param ocspResponsesId A resposta OCSP
	 */
	private void decodeOcspResponsesId(ASN1Object ocspResponsesId) {
		this.ocspIds.add(ocspResponsesId);
		String nameOrKeyHash = this.getOcspResponderId(ocspResponsesId);
		this.ocspIdsSet.add(nameOrKeyHash);
	}

	/**
	 * Retorna o identificador do atributo
	 * @return O identificador do atributo
	 */
	@Override
	public String getIdentifier() {
		return IdAaEtsRevocationRefs.IDENTIFIER;
	}

	/**
	 * Valida o atributo de acordo com suas regras específicas
	 * @throws SignatureAttributeException
	 */
	@Override
	public void validate() throws SignatureAttributeException {
		CertRevReq revocationRequirements = this.signatureVerifier.getSignaturePolicy().getSignerRevocationReqs();
		RevReq caRevReq = revocationRequirements.getCaCerts();
		RevReq endRevReq = revocationRequirements.getEndCertRevReq();
		boolean caValidationIsEitherCheck = caRevReq.getEnuRevReq() == RevReq.EnuRevReq.EITHER_CHECK;
		boolean caValidationIsCrlCheck = caRevReq.getEnuRevReq() == RevReq.EnuRevReq.CLR_CHECK;
		boolean caValidationIsOcspCheck = caRevReq.getEnuRevReq() == RevReq.EnuRevReq.OCSP_CHECK;
		boolean caValidationIsBothCheck = caRevReq.getEnuRevReq() == RevReq.EnuRevReq.BOTH_CHECK;
		boolean endValidationIsEitherCheck = endRevReq.getEnuRevReq() == RevReq.EnuRevReq.EITHER_CHECK;
		boolean endValidationIsCrlCheck = endRevReq.getEnuRevReq() == RevReq.EnuRevReq.CLR_CHECK;
		boolean endValidationIsBothCheck = endRevReq.getEnuRevReq() == RevReq.EnuRevReq.BOTH_CHECK;
		boolean caValidationCanBeCrl = caValidationIsEitherCheck || caValidationIsCrlCheck;
		boolean endValidationCanBeCrl = endValidationIsEitherCheck || endValidationIsCrlCheck;
		boolean endValidationIsOcspCheck = endRevReq.getEnuRevReq() == RevReq.EnuRevReq.OCSP_CHECK;
		boolean allValidationMustBeOcspCheck = caValidationIsOcspCheck && endValidationIsOcspCheck;
		boolean allValidationMustBeBothCheck = caValidationIsBothCheck && endValidationIsBothCheck;
		/* ocsp - ocsp */
		if (allValidationMustBeOcspCheck) {
			Set<BasicOCSPResponse> usedResponses = new HashSet<BasicOCSPResponse>();
			usedResponses.addAll(this.checkEndOcsp());
			usedResponses.addAll(this.checkCaOcsp());
			if (usedResponses.size() != this.ocspIds.size()) {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Há referências à respostas OCSP a mais no atributo IdAaRevocationRefs");
				signatureAttributeException.setCritical(this.isSigned());
				throw signatureAttributeException;
			}
		}
		/* both - both */
		if (allValidationMustBeBothCheck) {
			int sizeCrl;
			Set<BasicOCSPResponse> usedOcspResps = new HashSet<BasicOCSPResponse>();
			sizeCrl = this.checkEndCrl();
			sizeCrl += this.checkCaCrl();
			if (sizeCrl != this.crlIds.size()) {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Há referências à LCRs a mais no atributo IdAaRevocationRefs");
				signatureAttributeException.setCritical(this.isSigned());
				throw signatureAttributeException;
			}
			usedOcspResps.addAll(this.checkEndOcsp());
			usedOcspResps.addAll(this.checkCaOcsp());
			if (usedOcspResps.size() != this.ocspIds.size()) {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Há referências à respostas OCSP a mais no atributo IdAaRevocationRefs");
				signatureAttributeException.setCritical(this.isSigned());
				throw signatureAttributeException;
			}
		}
		/* crl - crl */
		if (endValidationCanBeCrl && caValidationCanBeCrl) {
			int size = this.checkEndCrl() + this.checkCaCrl();
			if (size < this.crlIds.size()) {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Há referências à LCRs a mais no atributo IdAaRevocationRefs");
				signatureAttributeException.setCritical(this.isSigned());
				throw signatureAttributeException;
			}
		}
		/* crl - ocsp */
		if (endValidationCanBeCrl && caValidationIsOcspCheck) {
			int usedCrls = 0;
			usedCrls = this.checkEndCrl();
			if (usedCrls != this.crlIds.size()) {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Há referências à LCRs a mais no atributo IdAaRevocationRefs");
				signatureAttributeException.setCritical(this.isSigned());
				throw signatureAttributeException;
			}
			Set<BasicOCSPResponse> usedResponses = new HashSet<BasicOCSPResponse>(this.checkCaOcsp());
			if (usedResponses.size() != this.ocspIds.size()) {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Há referências à respostas OCSP a mais no atributo IdAaRevocationRefs");
				signatureAttributeException.setCritical(this.isSigned());
				throw signatureAttributeException;
			}
		}
		/* ocsp - crl */
		if (endValidationIsOcspCheck && caValidationCanBeCrl) {
			Set<BasicOCSPResponse> usedResponses = new HashSet<BasicOCSPResponse>(this.checkEndOcsp());
			if (usedResponses.size() != this.ocspIds.size()) {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Há referências à respostas OCSP a mais no atributo IdAaRevocationRefs");
				signatureAttributeException.setCritical(this.isSigned());
				throw signatureAttributeException;
			}
			int usedCrls = 0;
			usedCrls = this.checkCaCrl();
			if (usedCrls != this.crlIds.size()) {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Há referências à LCRs a mais no atributo IdAaRevocationRefs");
				signatureAttributeException.setCritical(this.isSigned());
				throw signatureAttributeException;
			}
		}
		/* crl - both */
		if (endValidationCanBeCrl && caValidationIsBothCheck) {
			int usedCrls;
			usedCrls = this.checkEndCrl();
			usedCrls += this.checkCaCrl();
			Set<BasicOCSPResponse> usedOcspResps = new HashSet<BasicOCSPResponse>(this.checkCaOcsp());
			if (usedOcspResps.size() != this.ocspIds.size()) {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Há referências à respostas OCSP a mais no atributo IdAaRevocationRefs");
				signatureAttributeException.setCritical(this.isSigned());
				throw signatureAttributeException;
			}
			if (usedCrls != this.crlIds.size()) {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Há referências à LCRs a mais no atributo IdAaRevocationRefs");
				signatureAttributeException.setCritical(this.isSigned());
				throw signatureAttributeException;
			}
		}
		/* ocsp - both */
		if (endValidationIsOcspCheck && caValidationIsBothCheck) {
			Set<BasicOCSPResponse> usedResponses = new HashSet<BasicOCSPResponse>(this.checkEndOcsp());
			int usedCrls;
			usedCrls = this.checkCaCrl();
			usedResponses.addAll(this.checkCaOcsp());
			if (usedResponses.size() != this.ocspIds.size()) {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Há referências à respostas OCSP a mais no atributo IdAaRevocationRefs");
				signatureAttributeException.setCritical(this.isSigned());
				throw signatureAttributeException;
			}
			if (usedCrls != this.crlIds.size()) {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Há referências à LCRs a mais no atributo IdAaRevocationRefs");
				signatureAttributeException.setCritical(this.isSigned());
				throw signatureAttributeException;
			}
		}
		/* both - crl */
		if (endValidationIsBothCheck && caValidationCanBeCrl) {
			Set<BasicOCSPResponse> usedResponses = new HashSet<BasicOCSPResponse>(this.checkEndOcsp());
			int usedCrls;
			usedCrls = this.checkCaCrl();
			usedCrls += this.checkEndCrl();
			if (usedResponses.size() != this.ocspIds.size()) {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Há referências à respostas OCSP a mais no atributo IdAaRevocationRefs");
				signatureAttributeException.setCritical(this.isSigned());
				throw signatureAttributeException;
			}
			if (usedCrls != this.crlIds.size()) {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Há referências à LCRs a mais no atributo IdAaRevocationRefs");
				signatureAttributeException.setCritical(this.isSigned());
				throw signatureAttributeException;
			}
		}
		/* both - ocsp */
		if (endValidationIsBothCheck && caValidationIsOcspCheck) {
			Set<BasicOCSPResponse> usedResponses = new HashSet<BasicOCSPResponse>(this.checkEndOcsp());
			usedResponses = this.checkCaOcsp();
			int usedCrls;
			usedCrls = this.checkEndCrl();
			if (usedResponses.size() != this.ocspIds.size()) {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Há referências à respostas OCSP a mais no atributo IdAaRevocationRefs");
				signatureAttributeException.setCritical(this.isSigned());
				throw signatureAttributeException;
			}
			if (usedCrls != this.crlIds.size()) {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Há referências à LCRs a mais no atributo IdAaRevocationRefs");
				signatureAttributeException.setCritical(this.isSigned());
				throw signatureAttributeException;
			}
		}
	}

	/**
	 * Verifica quais respostas OCSP são usadas na validação do caminho de
	 * certificação das Autoridades Certificadoras(ACs). É verificado se existe
	 * alguma referência para essa resposta e ela é salva para depois
	 * contabiliza-la e garantir que o número de respostas utilizadas é o mesmo
	 * que o número de respostas referênciadas.
	 * @return Um conjunto de respostas OCSP, como respostas OCSP
	 *         indicam o status de validação de um ou mais certificados, o
	 *         conjunto foi usado para evitar redundâncias.
	 * @throws SignatureAttributeException É lançada caso não haja resposta OCSP para o certificado ou
	 *             caso a resposta que vai ser usada não está referênciada.
	 */
	@SuppressWarnings("unchecked")
	private Set<BasicOCSPResponse> checkCaOcsp()
			throws SignatureAttributeException {
		CertPath certPath = this.signatureVerifier.getCertPath();
		List<X509Certificate> certificates = (List<X509Certificate>) certPath
				.getCertificates();
		List<X509Certificate> caCertificates = certificates.subList(1,
				certificates.size());
		Set<BasicOCSPResponse> obtainedResponses = new HashSet<BasicOCSPResponse>();
		for (X509Certificate caCertificate : caCertificates) {
			BasicOCSPResponse resp = null;
			try {
				X509CertificateHolder caCert = new X509CertificateHolder(
						caCertificate.getEncoded());
				resp = this.getOcspRespFor(caCert);
			} catch (OCSPException ocspException) {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Não foi possível obter a resposta OCSP",
						ocspException.getStackTrace());
				signatureAttributeException.setCritical(this.isSigned());
				throw signatureAttributeException;
			} catch (IOException ioException) {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Não foi possível obter a resposta OCSP",
						ioException.getStackTrace());
				signatureAttributeException.setCritical(this.isSigned());
				throw signatureAttributeException;
			} catch (CertificateEncodingException certificateEncodingException) {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Não foi possível obter a resposta OCSP",
						certificateEncodingException.getStackTrace());
				signatureAttributeException.setCritical(this.isSigned());
				throw signatureAttributeException;
			}
			obtainedResponses.add(resp);
		}
		for (BasicOCSPResponse obtainedResp : obtainedResponses) {
			if (!this.match(obtainedResp)) {
				SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
						"Resposta OCSP faltando");
				signatureAttributeException.setCritical(this.isSigned());
				throw signatureAttributeException;
			}
		}
		return obtainedResponses;
	}

	/**
	 * Verifica qual a resposta que foi usada para validar o certificado final
	 * do caminho de certificação. É verificado se existe alguma referência a
	 * resposta OCSP encontrada. O retorno em forma de {@link Set} foi feito
	 * para simplificar a contagem de respostas OCSP usadas no total.
	 * @return Um conjunto que contém
	 *         unicamente a resposta usada para validar o certificado final
	 * @throws SignatureAttributeException É lançada caso não haja resposta OCSP para o certificado ou
	 *             caso a resposta que vai ser usada não está referênciada.
	 */
	private Set<BasicOCSPResponse> checkEndOcsp()
			throws SignatureAttributeException {
		CertPath certPath = this.signatureVerifier.getCertPath();
		BasicOCSPResponse ocspResponse = null;
		try {
			X509CertificateHolder endCertificate = new X509CertificateHolder(
					certPath.getCertificates().get(0).getEncoded());
			ocspResponse = this.getOcspRespFor(endCertificate);
		} catch (OCSPException ocspException) {
			SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
					"Não foi possível obter a resposta ocsp",
					ocspException.getStackTrace());
			signatureAttributeException.setCritical(this.isSigned());
			throw signatureAttributeException;
		} catch (IOException ioException) {
			SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
					"Não foi possível obter a resposta OCSP",
					ioException.getStackTrace());
			signatureAttributeException.setCritical(this.isSigned());
			throw signatureAttributeException;
		} catch (CertificateEncodingException certificateEncodingException) {
			SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
					"Não foi possível obter a resposta OCSP",
					certificateEncodingException.getStackTrace());
			signatureAttributeException.setCritical(this.isSigned());
			throw signatureAttributeException;
		}
		if (!this.match(ocspResponse)) {
			SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
					"Referência a resposta OCSP faltando");
			signatureAttributeException.setCritical(this.isSigned());
			throw signatureAttributeException;
		}
		return Collections.singleton(ocspResponse);
	}

	/**
	 * Verifica quais são as LCRs que foram usadas para validar os certificados
	 * das Autoridades Certificadoras(ACs) do caminho de certificação. Para cada
	 * LCRs é verificado se a referência para a mesma existe.
	 * @return O número de LCRs usadas
	 * @throws SignatureAttributeException É lançada quando não há LCR para o certificado em questão ou
	 *             quando não há referência a LCR encontrada.
	 */
	@SuppressWarnings("unchecked")
	private int checkCaCrl() throws SignatureAttributeException {
		CertPath certPath = this.signatureVerifier.getCertPath();
		List<X509Certificate> certificates = (List<X509Certificate>) certPath.getCertificates();
		List<X509Certificate> caCertificates = certificates.subList(1, certificates.size());
		X509CRLSelector selector = new X509CRLSelector();
		for (X509Certificate caCertificate : caCertificates) {
			selector.addIssuer(caCertificate.getIssuerX500Principal());
		}
		Set<X509CRL> crls = new HashSet<X509CRL>();
		
		crls.addAll(this.signatureVerifier.getCadesSignatureComponent().certificateValidation.getCRLs(selector, this.signatureVerifier.getTimeReference()));
		crls.addAll(this.signatureVerifier.getCadesSignatureComponent().getSignatureIdentityInformation().getCRLs(selector, this.signatureVerifier.getTimeReference()));

		Set<X509CRL> matchedCRLs = new HashSet<>();

		for (X509CRL crl : crls) {
			if (this.match(crl)) {
				matchedCRLs.add(crl);
			}
		}

		int size_except_end_crl = this.crlIds.size() - 1;
		if (matchedCRLs.size() < size_except_end_crl) {
			List<X509CRL> crls_ignoring_time = this.signatureVerifier.getCadesSignatureComponent().
					getSignatureIdentityInformation().getCRLs(selector, null);
			for(X509CRL crl : crls_ignoring_time) {
				if (this.match(crl)) {
					matchedCRLs.add(crl);
				}
			}
		}

		return matchedCRLs.size();
	}

	/**
	 * Verifica qual a LCR usada para verificar o certificado final do caminho
	 * de certificação. Para essa LCR é verificada se sua referência está
	 * presente no atributo.
	 * @return O número de LCRs usadas, que será sempre 1
	 * @throws SignatureAttributeException É lançada quando a LCR para validar o certificado final não
	 *             é encontrada ou quando não há referência para a mesma
	 */
	private int checkEndCrl() throws SignatureAttributeException {
		
		CertPath certPath = this.signatureVerifier.getCertPath();
		if (certPath == null) {
			SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
					"Não foi possível obter o caminho de certificação");
			signatureAttributeException.setCritical(this.isSigned());
			throw signatureAttributeException;
		}
		X509Certificate endCertificate = (X509Certificate) certPath.getCertificates().get(0);
		X509CRLSelector selector = new X509CRLSelector();
		selector.addIssuer(endCertificate.getIssuerX500Principal());
		Set<X509CRL> crls = new HashSet<X509CRL>();
		
		crls.addAll(this.signatureVerifier.getCadesSignatureComponent().certificateValidation.getCRLs(selector, this.signatureVerifier.getTimeReference()));
		crls.addAll(this.signatureVerifier.getCadesSignatureComponent().getSignatureIdentityInformation().getCRLs(selector, this.signatureVerifier.getTimeReference()));

		int i = 0;
		boolean control = false;
		while(i < crls.size() && !control) {
			if (this.match(crls.iterator().next()))
				control = true;
			i++;
		}
		
		if (!control) {
            List<X509CRL> crls_ignoring_time = this.signatureVerifier.getCadesSignatureComponent().getSignatureIdentityInformation().getCRLs(selector, null);
			i = 0;
            for(X509CRL crl : crls_ignoring_time) {
				if (this.match(crl))
					return crls_ignoring_time.size();
			}

            if (!control) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        "LCR referenciada não está presente");
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            }
		}
		return crls.size();
	}

	/**
	 * Busca a resposta OCSP para o certificado dado
	 * @param certificate O certificado
	 * @return A resposta OCSP obtida
	 * @throws OCSPException
	 * @throws IOException
	 */
	private BasicOCSPResponse getOcspRespFor(X509CertificateHolder certificate)
			throws OCSPException, IOException {
		BasicOCSPResponse result = null;
		Iterator<OCSPResp> i = this.signatureVerifier.getOcspList().iterator();
		while (i.hasNext() && result == null) {
			OCSPResp resp = i.next();
			BasicOCSPResp basicResp = (BasicOCSPResp) resp.getResponseObject();
			SingleResp[] responses = basicResp.getResponses();
			int j = 0;
			while (j < responses.length && result == null) {
				if (responses[j].getCertID().matchesIssuer(certificate, null)
						&& responses[j].getCertID().getSerialNumber()
								.equals(certificate.getSerialNumber())) {
					ASN1Sequence basicOCSPRespSequence = (ASN1Sequence) ASN1Sequence
							.fromByteArray(basicResp.getEncoded());
					BasicOCSPResponse basicOCSPResponse = BasicOCSPResponse
							.getInstance(basicOCSPRespSequence);
					result = basicOCSPResponse;
				}
				j++;
			}
		}
		return result;
	}

	/**
	 * Retorna o atributo codificado
	 * @return O atributo em formato ASN.1
	 */
	@Override
	public Attribute getEncoded() throws SignatureAttributeException {
		List<ASN1EncodableVector> crlOcspRefs = new ArrayList<ASN1EncodableVector>();
		if (this.crlIds != null && this.crlIds.size() > 0) {
			for (ASN1Encodable crlValidateId : this.crlIds) {
				ASN1EncodableVector crlOcspRefVector = new ASN1EncodableVector();
				ASN1TaggedObject crlListId = this.makeCrlListId(crlValidateId);
				crlOcspRefVector.add(crlListId);
				crlOcspRefs.add(crlOcspRefVector);
			}
		}

		if (this.ocspIds != null && this.ocspIds.size() > 0) {
			for (ASN1Encodable ocspResponsesId : this.ocspIds) {
				ASN1EncodableVector crlOcspRefVector = new ASN1EncodableVector();
				ASN1TaggedObject ocspListId = this
						.makeOcspListId(ocspResponsesId);
				crlOcspRefVector.add(ocspListId);
				crlOcspRefs.add(crlOcspRefVector);
			}
		}
		ASN1EncodableVector crlOcspRef = new ASN1EncodableVector();
		for (ASN1EncodableVector crlOcspRefVector : crlOcspRefs) {
			crlOcspRef.add(new DERSequence(crlOcspRefVector));
		}
		ASN1EncodableVector revocationRefsVector = new ASN1EncodableVector();
		revocationRefsVector.add(new DERSequence(crlOcspRef));
		// ASN1Sequence revocationRefs = new DERSequence(revocationRefsVector);
		DERSet set = new DERSet(revocationRefsVector);
		Attribute revocationRefsAttribute = new Attribute(
				new ASN1ObjectIdentifier(this.getIdentifier()), set);

		return revocationRefsAttribute;
	}

	/**
	 * Cria a entrada 'OcspListId' a partir das respostas OCSP
	 * @param ocspResponsesId As respostas OCSP
	 * @return Um objeto ASN.1
	 */
	private ASN1TaggedObject makeOcspListId(ASN1Encodable ocspResponsesId) {
		ASN1EncodableVector vector = new ASN1EncodableVector();
		// for (DEREncodable ocspResponsesId : this.ocspIds) {
		vector.add(ocspResponsesId);
		// }
		ASN1Encodable ocspListIdSequence = new DERSequence(vector);
		DERTaggedObject ocspListId = new DERTaggedObject(1, ocspListIdSequence);
		return ocspListId;
	}

	/**
	 * Cria a entrada 'CrlListId' a partir de um objeto 'crlValidateId'
	 * @param crlValidateId Um ASN.1 que contém 'crlValidateId'
	 * @return Um objeto ASN.1
	 */
	private ASN1TaggedObject makeCrlListId(ASN1Encodable crlValidateId) {
		ASN1EncodableVector vector = new ASN1EncodableVector();
		// for (DEREncodable crlValidateId : this.crlIds) {
		vector.add(crlValidateId);
		// }
		ASN1Encodable crls = new DERSequence(vector);
		ASN1EncodableVector crlList = new ASN1EncodableVector();
		crlList.add(crls);
		DERTaggedObject crlListId = new DERTaggedObject(0, new DERSequence(
				crlList));
		return crlListId;
	}

	/**
	 * Informa se o atributo é assinado
	 * @return Indica se o atributo é assinado
	 */
	@Override
	public boolean isSigned() {
		return false;
	}

	/**
	 * Preenche o conjunto de hashes de CRL com o valor de hash
	 * dos certificados na lista de identificadores de CRL
	 */
	private void makeCrlIdSet() {
		if(this.crlHashsSet == null)
			this.crlHashsSet = new HashSet<String>();
		if (this.crlIds != null) {
			for (ASN1Encodable crlValidateId : this.crlIds) {
				byte[] crlHash = this.getCrlHashFromValidateId(crlValidateId);
				this.crlHashsSet.add(new String(Base64.encode(crlHash)));
			}
		}
	}

	/**
	 * Calcula o hash de uma entrada 'ValidateId'
	 * @param crlValidateId A entrada 'ValidateId'
	 * @return Os bytes do hash
	 */
	private byte[] getCrlHashFromValidateId(ASN1Encodable crlValidateId) {
		ASN1Sequence crlValidateIdSequence = (ASN1Sequence) crlValidateId;
		ASN1Encodable otherHash = (ASN1Encodable) crlValidateIdSequence
				.getObjectAt(0);
		byte[] result = null;
		if (otherHash instanceof ASN1OctetString) {
			ASN1OctetString hashValue = (ASN1OctetString) otherHash;
			result = hashValue.getOctets();
			this.algorithm = CMSSignedGenerator.DIGEST_SHA1;
		} else {
			OtherHashAlgAndValue hashAlgAndValue = (otherHash instanceof ASN1Sequence) ? OtherHashAlgAndValue
					.getInstance(otherHash) : (OtherHashAlgAndValue) otherHash;
			// OtherHashAlgAndValue hashAlgAndValue = (OtherHashAlgAndValue)
			// otherHash;
			this.algorithm = hashAlgAndValue.getHashAlgorithm().getAlgorithm().getId();
			result = hashAlgAndValue.getHashValue().getOctets();
		}
		return result;
	}

	/**
	 * Preenche o conjunto de identificadores de OCSP com o valor de hash
	 * da lista de respostas OCSP
	 */
	private void makeOcspIdSet() {
		if(this.ocspIdsSet == null)
			this.ocspIdsSet = new HashSet<String>();
		if (this.ocspIds != null) {
			for (ASN1Encodable ocspResponseId : this.ocspIds) {
				this.ocspIdsSet.add(new String(Base64.encode(this
						.getOcspResponseHash((ASN1Sequence) ocspResponseId))));
			}
		}
	}

	/**
	 * Calcula o hash da resposta OCSP
	 * @param ocspResponseId A resposta OCSP
	 * @return O hash em formato de String
	 */
	private String getOcspResponderId(ASN1Encodable ocspResponseId) {
		String result = null;
		ASN1Sequence ocspResponsesIdSequence = (ASN1Sequence) ocspResponseId;
		ASN1Sequence ocspIdentifier = (ASN1Sequence) ocspResponsesIdSequence
				.getObjectAt(0);
		ASN1TaggedObject responderIdTagged = null;
		if (ocspIdentifier.getObjectAt(0) instanceof ResponderID) {
			ResponderID responderId = (ResponderID) ocspIdentifier
					.getObjectAt(0);
			responderIdTagged = (ASN1TaggedObject) responderId
					.toASN1Primitive();
		} else {
			responderIdTagged = (ASN1TaggedObject) ocspIdentifier
					.getObjectAt(0);
		}
		if (responderIdTagged.getTagNo() == 1) {
			result = responderIdTagged.getObject().toString();
		} else {
			ASN1OctetString keyHash = (ASN1OctetString) responderIdTagged
					.getObject();
			result = new String(Base64.encode(keyHash.getOctets()));
		}
		return result;
	}

	/**
	 * Calcula o hash da resposta OCSP
	 * @param ocspResponseId A resposta OCSP
	 * @return Os bytes do hash
	 */
	private byte[] getOcspResponseHash(ASN1Sequence ocspResponseId) {
		byte[] result = null;
		ASN1Encodable otherHash = (ASN1Encodable) ocspResponseId.getObjectAt(1);
		if (otherHash instanceof ASN1OctetString) {
			ASN1OctetString octetStream = (ASN1OctetString) otherHash;
			result = octetStream.getOctets();
			this.algorithm = CMSSignedGenerator.DIGEST_SHA1;
		} else {
			OtherHashAlgAndValue otherHashAlgAndValue = (OtherHashAlgAndValue) otherHash;
			this.algorithm = AlgorithmIdentifierMapper
					.getAlgorithmNameFromIdentifier(otherHashAlgAndValue
							.getHashAlgorithm().toString());
			result = otherHashAlgAndValue.getHashValue().getOctets();
		}
		return result;
	}

	/**
	 *
	 * @param basicOCSPResponses
	 * @param algorithm
	 * @throws SignatureAttributeException
	 */
	private void makeOcspIdentifiers(
			List<BasicOCSPResponse> basicOCSPResponses, String algorithm)
			throws SignatureAttributeException {
		if (basicOCSPResponses == null || basicOCSPResponses.size() == 0) {
			throw new SignatureAttributeException(
					"Não é possível construir o attributo com uma lista de respostas OCSP vazia usando esse construtor");
		}
		this.ocspIds = new ArrayList<ASN1Encodable>();
		for (BasicOCSPResponse response : basicOCSPResponses) {
			ASN1Encodable ocspResponsesId = this.getOcspResponsesId(response,
					algorithm);
			this.ocspIds.add(ocspResponsesId);
		}
	}

	/**
	 * 
	 * CRLListID ::= SEQUENCE { crls SEQUENCE OF CrlValidatedID }
	 * 
	 * @param crls
	 *            - The crls to add in the attribute
	 * @param algorithm
	 *            - The hash algorithm that should be used
	 * @throws SignatureAttributeException
	 */
	private void makeCrlIdentifiers(List<X509CRL> crls, String algorithm)
			throws SignatureAttributeException {
		if (crls == null || crls.size() == 0) {
			throw new SignatureAttributeException(
					"Não é possível construir o attributo com uma lista de CRLs vazia usando esse construtor");
		}
		this.crlIds = new ArrayList<ASN1Encodable>();
		for (X509CRL crl : crls) {
			ASN1Encodable crlValidateId = this.getCrlValidateId(crl, algorithm);
			this.crlIds.add(crlValidateId);
		}
	}

	/**
	 * CrlIdentifier ::= Sequence { crlIssuer Name, crlIssuedTime UTCTime,
	 * crlNumber Integer OPTIONAL }
	 * 
	 * @return {@link DERSequence}
	 */
	private ASN1Encodable getCrlIdentifier(String crlIssuer,
			Time crlIssuedTime, BigInteger crlNumber) {
		ASN1EncodableVector vector = new ASN1EncodableVector();
		X500Name name = new X500Name(crlIssuer);
		vector.add(name);
		vector.add(crlIssuedTime);
		if (crlNumber != null) {
			ASN1Integer derCrlNumber = new ASN1Integer(crlNumber);
			vector.add(derCrlNumber);
		}
		return new DERSequence(vector);
	}

	/**
	 * CrlValidatedID ::= { crlHash OtherHash crlIdentifier CrlIdentifier
	 * OPTIONAL }
	 * 
	 * @throws SignatureAttributeException
	 */
	private ASN1Encodable getCrlValidateId(X509CRL crl, String algorithm)
			throws SignatureAttributeException {
		ASN1EncodableVector vector = new ASN1EncodableVector();
		try {
			vector.add(this.getOtherHash(crl.getEncoded(), algorithm));
		} catch (CRLException crlException) {
			throw new SignatureAttributeException(
					SignatureAttributeException.PROBLEMS_TO_DECODE
							+ this.getIdentifier());
		}
		vector.add(this.getCrlIdentifier(
				crl.getIssuerX500Principal().toString(),
				new Time(crl.getThisUpdate()), null));
		return new DERSequence(vector);
	}

	private ASN1Encodable getOtherHash(byte[] data, String algorithm)
			throws SignatureAttributeException {
		ASN1Encodable result = null;
		String algorithmName = AlgorithmIdentifierMapper
				.getAlgorithmNameFromIdentifier(algorithm);
		MessageDigest digester = null;
		if (algorithmName != null) {
			try {
				digester = MessageDigest.getInstance(algorithmName);
			} catch (NoSuchAlgorithmException noSuchAlgorithmException) {
				throw new SignatureAttributeException(
						SignatureAttributeException.NO_SUCH_ALGORITHM,
						noSuchAlgorithmException.getStackTrace());
			}
		} else {
			throw new SignatureAttributeException(
					SignatureAttributeException.NO_SUCH_ALGORITHM);
		}
		byte[] hash = null;
		hash = digester.digest(data);
		if (algorithmName.equals("sha-1")) {
			ASN1OctetString otherHashValue = ASN1OctetString.getInstance(hash);
			result = otherHashValue;
		} else {
			ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(algorithm);
			AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(oid);
			ASN1OctetString hashValue = new DEROctetString(hash);
			
			OtherHashAlgAndValue hashAlgAndValue = new OtherHashAlgAndValue(
					algorithmIdentifier, hashValue);
			result = hashAlgAndValue;
		}
		return result;
	}

	private ASN1Encodable getOcspIdentifier(RespID respID, Time producedAt) {
		ASN1EncodableVector vector = new ASN1EncodableVector();
		vector.add(respID.toASN1Primitive());
		vector.add(producedAt);
		return new DERSequence(vector);
	}

	private ASN1Encodable getOcspResponsesId(
			BasicOCSPResponse basicOCSPResponse, String algorithm)
			throws SignatureAttributeException {
		BasicOCSPResp basicOcspResp = new BasicOCSPResp(basicOCSPResponse);
		ASN1EncodableVector vector = new ASN1EncodableVector();
		vector.add(this.getOcspIdentifier(basicOcspResp.getResponderId(),
				new Time(basicOcspResp.getProducedAt())));
		try {
			vector.add(this.getOtherHash(basicOCSPResponse.getEncoded(),
					algorithm));
		} catch (IOException ioException) {
			throw new SignatureAttributeException(
					SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + IdAaEtsRevocationRefs.IDENTIFIER,
					ioException.getStackTrace());
		}
		return new DERSequence(vector);
	}

	@Override
	public IdAaEtsRevocationRefs clone() {
		IdAaEtsRevocationRefs clone = new IdAaEtsRevocationRefs();
		clone.algorithm = this.algorithm;
		clone.crlHashsSet = new HashSet<String>(this.crlHashsSet);
		clone.crlIds = new ArrayList<ASN1Encodable>(this.crlIds);
		clone.ocspIds = new ArrayList<ASN1Encodable>(this.ocspIds);
		clone.ocspIdsSet = new HashSet<String>(this.ocspIdsSet);
		return clone;
	}

	@Override
	public boolean match(CRL crl) {
		boolean result = false;
		boolean error = false;
		String algorithmName = AlgorithmIdentifierMapper
				.getAlgorithmNameFromIdentifier(this.algorithm);
		MessageDigest digester = null;
		try {
			digester = MessageDigest.getInstance(algorithmName);
		} catch (NoSuchAlgorithmException noSuchAlgorithmException) {
			// Não é possível selecionar as LCRs
			error = true;
			noSuchAlgorithmException.printStackTrace();
		}
		X509CRL x509Crl = (X509CRL) crl;
		byte[] crlDigest = null;
		try {
			crlDigest = digester.digest(x509Crl.getEncoded());
		} catch (CRLException crlException) {
			// Não é possível codificar a LCR para obter o valor hash
			error = true;
			crlException.printStackTrace();
		}
		String crlDigestBase64 = new String(Base64.encode(crlDigest));
		if (!error) {
			result = this.crlHashsSet.contains(crlDigestBase64);
		}
		return result;
	}

	/**
	 * Seleciona em uma lista de respostas OCSP apenas aquelas que são
	 * referênciadas por este atributo
	 * @param responses A lista de respostas OCSP
	 * @return As respostas na lista que são referênciadas por este atributo
	 * @throws SignatureAttributeException
	 */
	public List<BasicOCSPResponse> selectOcspResponses(
			List<BasicOCSPResponse> responses)
			throws SignatureAttributeException {
		List<BasicOCSPResponse> selectedResponses = new ArrayList<BasicOCSPResponse>();
		for (BasicOCSPResponse response : responses) {
			if (this.match(response)) {
				selectedResponses.add(response);
			}
		}
		return selectedResponses;
	}

	/**
	 * Indica se a resposta OCSP está presente ou não no atributo.
	 * 
	 * @param response
	 *            - {@link BasicOCSPResponse}
	 * 
	 * @return boolean
	 * 
	 * @throws SignatureAttributeException
	 */
	public boolean match(BasicOCSPResponse response)
			throws SignatureAttributeException {
		boolean result = false;
		MessageDigest digester = null;
		try {
			digester = MessageDigest.getInstance(AlgorithmIdentifierMapper
					.getAlgorithmNameFromIdentifier(this.algorithm));
		} catch (NoSuchAlgorithmException noSuchAlgorithmException) {
			throw new SignatureAttributeException(
					SignatureAttributeException.NO_SUCH_ALGORITHM);
		}
		byte[] hash = null;
		try {
			hash = digester.digest(response.getEncoded());
		} catch (IOException ioException) {
			throw new SignatureAttributeException(
					SignatureAttributeException.HASH_FAILURE,
					ioException.getStackTrace());
		}
		String obtainedHash = new String(Base64.encode(hash));
		result = this.ocspIdsSet.contains(obtainedHash);
		return result;
	}

	public List<ASN1Encodable> getCrlIds() {
		return crlIds;
	}

	public List<ASN1Encodable> getOcspIds() {
		return ocspIds;
	}

	/**
	 * Verifica se o atributo deve ter apenas uma instância na assinatura
	 * @return Indica se o atributo deve ter apenas uma instância na assinatura
	 */
	@Override
	public boolean isUnique() {
		return true;
	}
}
