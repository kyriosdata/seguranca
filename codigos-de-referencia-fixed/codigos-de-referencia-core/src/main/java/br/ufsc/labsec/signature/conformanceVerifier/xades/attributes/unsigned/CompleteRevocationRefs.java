/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned;

import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.CertRevReq;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.RevReq;
import br.ufsc.labsec.signature.conformanceVerifier.xades.*;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.sql.Time;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * 
 * Este atributo deve conter apenas todas LCRs ou respostas OCSP do caminho de
 * certificação do assinante.
 * Somente uma instância deste atributo é permitida na assinatura.
 * 
 * Esquema do atributo CompleteRevocationRefs retirado do ETSI TS 101 903:
 * 
 * {@code
 * <xsd:element name="CompleteRevocationRefs" type="CompleteRevocationRefsType"/>
 *  
 * <xs:complexType name="CompleteRevocationRefsType">
 * <xs:sequence>
 *   <xs:element name="CRLRefs" type="CRLRefsType" minOccurs="0"/>
 *   <xs:element name="OCSPRefs" type="OCSPRefsType" minOccurs="0"/>
 *   <xs:element name="OtherRefs" type="OtherCertStatusRefsType" minOccurs="0"/>
 * </xs:sequence>
 * <xs:attribute name="Id" type="xs:ID" use="optional"/>
 * </xs:complexType>
 * }
 */
public class CompleteRevocationRefs implements SignatureAttribute, CRLSelector {

    public static final String IDENTIFIER = "CompleteRevocationRefs";
    private static final String UNKNOWN_HASH_ALGORITHM = "O Algoritmo de hash não é conhecido: ";
    private static final String HAS_MORE_REFERENCES_THAN_OCSP_ANSWERS = "Há referências à respostas OCSP a mais no atributo CompleteRevocationRefs";
    private static final String DIGEST_ALG_AND_VALUE = "DigestAlgAndValue";
    private static final String CRL_NUMBER = "2.5.29.20";
    private static final String ALGORITHM = "Algorithm";
    private static final String DIGEST_VALUE = "DigestValue";
    private static final String DIGEST_METHOD = "DigestMethod";
    /**
     * O algoritmo de hash utilizado
     */
    private String algorithm;
    /**
     * Lista de referências de CRL
     */
    private List<CRLRefs> crlRefs;
    /**
     * Lista de referências de OCSP
     */
    private List<OCSPRefs> ocspRefs;
    /**
     * Conjunto de identificadores (valor de hash) de CRLs e respostas OCSP
     */
    private Set<String> crlAndOcspIdSet;
    /**
     * Objeto de verificador
     */
    private SignatureVerifier signatureVerifier;

    /**
     * Construtor usado para validar o atributo
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * @throws SignatureAttributeException
     */
    public CompleteRevocationRefs(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        this.signatureVerifier = (SignatureVerifier) signatureVerifier;
        XadesSignature signature = signatureVerifier.getSignature();
        Element encodedAttribute = signature.getEncodedAttribute(this.getIdentifier(), index);
        this.decode(encodedAttribute);
    }

    /**
     * Construtor usado para decodificar um atributo já existente. Útil na
     * validação para selecionar as LCRs ou respostas OCSP relevantes
     * @param genericEncoding O atributo codificado
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos
     *             atributos da assinatura
     */
    public CompleteRevocationRefs(Element genericEncoding) throws SignatureAttributeException {
        this.decode(genericEncoding);
    }

    /**
     * Cria o atributo com os dados de revogação tanto no formato de LCRs quanto
     * de respostas OCSP.
     * 
     * @param crls Lista de CRLs do caminho de certificação
     * @param basicOCSPResponses Lista de respostas OCSPs para o caminho de
     *            certificação
     * @param digestAlgorithm Identificador do algoritmo de hash utilizado
     *            sobre as referências
     * 
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos
     *             atributos da assinatura
     */
    public CompleteRevocationRefs(List<X509CRL> crls, List<BasicOCSPResponse> basicOCSPResponses, String digestAlgorithm)
            throws SignatureAttributeException {
        this.setAlgorithm(digestAlgorithm);
        this.makeCrlRefList(crls, digestAlgorithm);
        this.makeOcspRefList(basicOCSPResponses, digestAlgorithm);
        this.makeCrlAndOcspIdSet();
    }

    /**
     * Cria o atributo que irá referênciar as LCRs passadas na lista. Nas
     * referências será usado um algoritmo de hash, o identificador de qual o
     * algoritmo a ser usado deve ser passado através do
     * <code>digestAlgorithm</code>
     * 
     * @param crls Lista de CRLs do caminho de certificação
     * @param digestAlgorithm Identificador do algoritmo de hash utilizado
     *            sobre as referências
     * 
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos
     *             atributos da assinatura
     */
    public CompleteRevocationRefs(List<X509CRL> crls, String digestAlgorithm) throws SignatureAttributeException {
        this.setAlgorithm(digestAlgorithm);
        this.makeCrlRefList(crls, digestAlgorithm);
        this.makeCrlAndOcspIdSet();
        this.ocspRefs = new ArrayList<OCSPRefs>();
    }

    /**
     * Cria o atributo que irá referênciar as respostas OCSP passadas na lista.
     * Nas referências será usado um algoritmo de hash, o identificador de qual
     * o algoritmo a ser usado deve ser passado através do
     * <code>digestAlgorithm</code>
     * 
     * @param digestAlgorithm Identificador do algoritmo de hash utilizado
     *            sobre as referências
     * @param basicOCSPResponses Lista de respostas OCSPs para o caminho de
     *            certificação
     * 
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos
     *             atributos da assinatura
     */
    public CompleteRevocationRefs(String digestAlgorithm, List<BasicOCSPResponse> basicOCSPResponses) throws SignatureAttributeException {
        this.setAlgorithm(digestAlgorithm);
        this.makeOcspRefList(basicOCSPResponses, digestAlgorithm);
        this.makeCrlAndOcspIdSet();
    }

    /**
     * Constrói um objeto {@link CompleteRevocationRefs}
     * @param attributeElement Atributo a ser decodificado
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos
     *             atributos da assinatura
     */
    private void decode(Element attributeElement) throws SignatureAttributeException {
        NodeList crlRefsList = attributeElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "CRLRefs");
        if (crlRefsList.getLength() > 0) {
            parseCrlRefs(crlRefsList);
        }
        NodeList ocspRefsList = attributeElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "OCSPRefs");
        if (ocspRefsList.getLength() > 0) {
            parseOcspRefs(ocspRefsList);
        }
        this.makeCrlAndOcspIdSet();
    }

    /**
     * Faz o parsing das referências do serviço de OCSP
     * @param ocspRefsList Lista de referências de OCSP
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos
     *             atributos da assinatura
     */
    private void parseOcspRefs(NodeList ocspRefsList) throws SignatureAttributeException {
        this.ocspRefs = new ArrayList<OCSPRefs>();
        Element ocspRefsElement = (Element) ocspRefsList.item(0);
        NodeList ocspRefList = ocspRefsElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "OCSPRef");
        for (int i = 0; i < ocspRefList.getLength(); i++) {
            Element ocspRef = (Element) ocspRefList.item(i);
            Element certDigestElement = (Element) ocspRef.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, DIGEST_ALG_AND_VALUE)
                    .item(0);
            Element digestMethodElement = (Element) certDigestElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS,
                    DIGEST_METHOD).item(0);
            this.algorithm = digestMethodElement.getAttribute(ALGORITHM);
            Element digestValueElement = (Element) certDigestElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS,
                    DIGEST_VALUE).item(0);
            OCSPRefs ocsp = new OCSPRefs();
            ocsp.setAlgorithm(this.algorithm);
            ocsp.setDigestValue(digestValueElement.getTextContent());
            this.ocspRefs.add(ocsp);
        }
    }

    /**
     * Faz o parsing das referências da lista de certificados revogados
     * @param crlRefsList Lista de referências da lista de certificados
     *            revogados
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos
     *             atributos da assinatura
     */
    private void parseCrlRefs(NodeList crlRefsList) throws SignatureAttributeException {
        this.crlRefs = new ArrayList<CRLRefs>();
        Element crlRefs = (Element) crlRefsList.item(0);
        NodeList crlRefList = crlRefs.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "CRLRef");
        for (int i = 0; i < crlRefList.getLength(); i++) {
            Element crlRef = (Element) crlRefList.item(i);
            Element certDigestElement = (Element) crlRef.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, DIGEST_ALG_AND_VALUE)
                    .item(0);
            Element digestMethodElement = (Element) certDigestElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS,
                    DIGEST_METHOD).item(0);
            this.algorithm = digestMethodElement.getAttribute(ALGORITHM);
            Element digestValueElement = (Element) certDigestElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS,
                    DIGEST_VALUE).item(0);
            CRLRefs ref = new CRLRefs();
            ref.setAlgorithm(this.algorithm);
            ref.setDigestValue(digestValueElement.getTextContent());
            this.crlRefs.add(ref);
        }
    }

    /**
     * Muda o algoritmo utilizado por esta classe
     * @param algorithm Identificador do algoritmo
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos
     *             atributos da assinatura
     */
    private void setAlgorithm(String algorithm) throws SignatureAttributeException {
        if (algorithm == null)
            throw new SignatureAttributeException("O algoritmo não pode ser nulo");
        String obtainedIdentifier = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithm);
        if (obtainedIdentifier == null)
            throw new SignatureAttributeException("O algoritmo indicado é desconhecido");
        this.algorithm = algorithm;
    }

    /**
     * Inicializa o conjunto de identificadores de LCRs e respostas OCSP
     * adicionando o hash de cada uma ao conjunto
     */
    private void makeCrlAndOcspIdSet() {
        this.crlAndOcspIdSet = new HashSet<String>();
        if (this.crlRefs != null) {
            for (CRLRefs crlId : this.crlRefs) {
                this.crlAndOcspIdSet.add(crlId.getDigestValue());
            }
        }
        if (this.ocspRefs != null) {
            for (OCSPRefs ocspId : this.ocspRefs) {
                this.crlAndOcspIdSet.add(ocspId.getDigestValue());
            }
        }
    }

    /**
     * Faz uma lista das referências de serviços OCSP
     * @param basicOCSPResponses Resposta básica do serviço de OCSP
     * @param algorithm Identificador do algoritmo utilizado
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos
     *             atributos da assinatura
     */
    private void makeOcspRefList(List<BasicOCSPResponse> basicOCSPResponses, String algorithm) throws SignatureAttributeException {
        if (basicOCSPResponses == null || basicOCSPResponses.size() == 0)
            throw new SignatureAttributeException("Esse construtor não deve ser usado se não há nenhuma resposta OCSP para referênciar");
        this.ocspRefs = new ArrayList<OCSPRefs>();
        for (BasicOCSPResponse basicOCSPResponse : basicOCSPResponses) {
            this.makeOcspReference(algorithm, basicOCSPResponse);
        }
    }

    /**
     * Faz a referência do serviço de OCSP passado como parâmetro
     * @param algorithm Identificador do algoritmo utilizado
     * @param basicOCSPResponse Resposta básica do serviço de OCSP
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos
     *             atributos da assinatura
     */
    private void makeOcspReference(String algorithm, BasicOCSPResponse basicOCSPResponse) throws SignatureAttributeException {
        OCSPRefs ocspRef = new OCSPRefs();
        BasicOCSPResp basicOcspResp = new BasicOCSPResp(basicOCSPResponse);

        ocspRef.setProducedAt((new Time(basicOcspResp.getProducedAt().getTime())));
        RespID responderIdEncoded = basicOcspResp.getResponderId();
        ASN1Object responderIdChoice = responderIdEncoded.toASN1Primitive();
        DERTaggedObject responderIdTaggedObject = (DERTaggedObject) responderIdChoice;
        if (responderIdTaggedObject.getTagNo() == 1) {
            try {
                ocspRef.setResponderName(new String(responderIdTaggedObject.getEncoded()));
            } catch (IOException e) {
                throw new SignatureAttributeException("ResponderName não pode ser setado", e.getStackTrace());
            }
        } else {
            try {
                ocspRef.setResponderKey(responderIdTaggedObject.getEncoded());
            } catch (IOException e) {
                throw new SignatureAttributeException("ResponderKey não pode ser setado", e.getStackTrace());
            }
        }
        addOcspRef(algorithm, basicOCSPResponse, ocspRef);
    }

    /**
     * Adiciona referências a determinado serviço OCSP
     * @param algorithm Identificador do algoritmo utilizado
     * @param basicOCSPResponse Resposta básica do serviço de OCSP
     * @param ocspRef Referência do serviço OCSP utilizado
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos
     *             atributos da assinatura
     */
    private void addOcspRef(String algorithm, BasicOCSPResponse basicOCSPResponse, OCSPRefs ocspRef) throws SignatureAttributeException {
        ocspRef.setAlgorithm(algorithm);

        byte[] ocspDigestValue = null;
        MessageDigest digester = null;
        try {
            digester = MessageDigest.getInstance(AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithm));
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new SignatureAttributeException(UNKNOWN_HASH_ALGORITHM + algorithm, noSuchAlgorithmException.getStackTrace());
        }
        try {
            ocspDigestValue = digester.digest(basicOCSPResponse.getEncoded());
        } catch (IOException ioException) {
            throw new SignatureAttributeException("Não foi possível codificar a resposta OCSP", ioException.getStackTrace());
        }

        ocspRef.setDigestValue(new String(ocspDigestValue));
        this.ocspRefs.add(ocspRef);
    }

    /**
     * Monta as referências das listas de certificados revogados
     * @param crls Listas de certificados revogados
     * @param algorithm Identificador do algoritmo
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos
     *             atributos da assinatura
     */
    private void makeCrlRefList(List<X509CRL> crls, String algorithm) throws SignatureAttributeException {
        if (crls == null || crls.size() == 0)
            throw new SignatureAttributeException("Não se deve usar esse construtor se não há LCRs para serem referenciadas");
        this.crlRefs = new ArrayList<CRLRefs>();
        for (X509CRL crl : crls) {
            this.makeCrlReference(algorithm, crl);
        }
    }

    /**
     * Monta as referencias da lista de certificados revogados
     * @param algorithm Identificador do algoritmo
     * @param crl Lista de certificados revogados
     * @throws SignatureAttributeException Lista de certificados revogados
     */
    private void makeCrlReference(String algorithm, X509CRL crl) throws SignatureAttributeException {
        CRLRefs crlRef = new CRLRefs();
        crlRef.setName(crl.getIssuerX500Principal().toString());
        crlRef.setIssueTime(new Time(crl.getThisUpdate().getTime()));

        Set<String> nonCriticalExtensions = crl.getNonCriticalExtensionOIDs();
        if (nonCriticalExtensions.contains(CRL_NUMBER)) {
            BigInteger crlNumber = new BigInteger(crl.getExtensionValue(CRL_NUMBER));
            crlRef.setCrlNumber(crlNumber);
        }
        crlRef.setAlgorithm(algorithm);
        MessageDigest digester = null;
        byte[] hash = null;
        try {
            digester = MessageDigest.getInstance(AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithm));
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new SignatureAttributeException(UNKNOWN_HASH_ALGORITHM + algorithm, noSuchAlgorithmException.getStackTrace());
        }
        try {
            hash = digester.digest(crl.getEncoded());
        } catch (CRLException crlException) {
            throw new SignatureAttributeException("Não foi possível codificar a crl", crlException.getStackTrace());
        }
        crlRef.setDigestValue(new String(Base64.encode(hash)));
        this.crlRefs.add(crlRef);
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return CompleteRevocationRefs.IDENTIFIER;
    }

    /**
     * Valida o atributo de acordo com suas regras específicas
     * @throws SignatureAttributeException
     */
    @Override
    public void validate() throws SignatureAttributeException {
        // FIXME : Arrumar
        CertRevReq revocationRequirements = this.signatureVerifier.getSignaturePolicy().getSignerRevocationReqs();
        RevReq caRevReq = revocationRequirements.getCaCerts();
        RevReq endRevReq = revocationRequirements.getEndCertRevReq();
        boolean caValidationIsEitherCheck = caRevReq.getEnuRevReq() == RevReq.EnuRevReq.EITHER_CHECK;
        boolean caValidationIsCrlCheck = caRevReq.getEnuRevReq() == RevReq.EnuRevReq.CLR_CHECK;
        boolean caValidationIsOcspCheck = endValidationIsOcspCheck(caRevReq);
        boolean caValidationIsBothCheck = caRevReq.getEnuRevReq() == RevReq.EnuRevReq.BOTH_CHECK;
        boolean endValidationIsEitherCheck = endRevReq.getEnuRevReq() == RevReq.EnuRevReq.EITHER_CHECK;
        boolean endValidationIsCrlCheck = endRevReq.getEnuRevReq() == RevReq.EnuRevReq.CLR_CHECK;
        boolean endValidationIsBothCheck = endRevReq.getEnuRevReq() == RevReq.EnuRevReq.BOTH_CHECK;
        boolean caValidationCanBeCrl = endValidationCanBeCrl(caValidationIsEitherCheck, caValidationIsCrlCheck);
        /* ocsp - ocsp */

        verifyIfAllValidationMustBeOcspCheck(endRevReq, caValidationIsOcspCheck);
        /* both - both */
        if (allValidationMustBeOcspCheck(caValidationIsOcspCheck, endValidationIsOcspCheck(endRevReq))) {
            int sizeCrl;
            Set<BasicOCSPResponse> usedOcspResps = new HashSet<BasicOCSPResponse>();
            sizeCrl = this.checkEndCrl();
            sizeCrl += this.checkCaCrl();
            if (sizeCrl != this.crlRefs.size()) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        HAS_MORE_REFERENCES_THAN_OCSP_ANSWERS);
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            }
            usedOcspResps.addAll(this.checkEndOcsp());
            usedOcspResps.addAll(this.checkCaOcsp());
            if (usedOcspResps.size() != this.ocspRefs.size()) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        HAS_MORE_REFERENCES_THAN_OCSP_ANSWERS);
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            }
        }
        /* crl - crl */
        verifyIfEndValidationIsEitherCheck(endValidationIsEitherCheck, endValidationIsCrlCheck, caValidationCanBeCrl);
        /* crl - ocsp */
        if (endValidationCanBeCrl(endValidationIsEitherCheck, endValidationIsCrlCheck) && caValidationIsOcspCheck) {
            int usedCrls = 0;
            usedCrls = this.checkEndCrl();
            if (usedCrls != this.crlRefs.size()) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        HAS_MORE_REFERENCES_THAN_OCSP_ANSWERS);
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            }
            Set<BasicOCSPResponse> usedResponses = new HashSet<BasicOCSPResponse>(this.checkCaOcsp());
            if (usedResponses.size() != this.ocspRefs.size()) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        HAS_MORE_REFERENCES_THAN_OCSP_ANSWERS);
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            }
        }
        /* ocsp - crl */
        if (endValidationIsOcspCheck(endRevReq) && caValidationCanBeCrl) {
            Set<BasicOCSPResponse> usedResponses = new HashSet<BasicOCSPResponse>(this.checkEndOcsp());
            if (usedResponses.size() != this.ocspRefs.size()) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        HAS_MORE_REFERENCES_THAN_OCSP_ANSWERS);
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            }
            int usedCrls = 0;
            usedCrls = this.checkCaCrl();
            if (usedCrls != this.crlRefs.size()) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        HAS_MORE_REFERENCES_THAN_OCSP_ANSWERS);
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            }
        }
        /* crl - both */
        if (endValidationCanBeCrl(endValidationIsEitherCheck, endValidationIsCrlCheck) && caValidationIsBothCheck) {
            int usedCrls;
            usedCrls = this.checkEndCrl();
            usedCrls += this.checkCaCrl();
            Set<BasicOCSPResponse> usedOcspResps = new HashSet<BasicOCSPResponse>(this.checkCaOcsp());
            if (usedOcspResps.size() != this.ocspRefs.size()) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        HAS_MORE_REFERENCES_THAN_OCSP_ANSWERS);
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            }
            if (usedCrls != this.crlRefs.size()) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        HAS_MORE_REFERENCES_THAN_OCSP_ANSWERS);
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            }
        }
        /* ocsp - both */
        if (endValidationIsOcspCheck(endRevReq) && caValidationIsBothCheck) {
            Set<BasicOCSPResponse> usedResponses = new HashSet<BasicOCSPResponse>(this.checkEndOcsp());
            int usedCrls;
            usedCrls = this.checkCaCrl();
            usedResponses.addAll(this.checkCaOcsp());
            if (usedResponses.size() != this.ocspRefs.size()) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        HAS_MORE_REFERENCES_THAN_OCSP_ANSWERS);
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            }
            if (usedCrls != this.crlRefs.size()) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        HAS_MORE_REFERENCES_THAN_OCSP_ANSWERS);
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
            if (usedResponses.size() != this.ocspRefs.size()) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        HAS_MORE_REFERENCES_THAN_OCSP_ANSWERS);
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            }
            if (usedCrls != this.crlRefs.size()) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        HAS_MORE_REFERENCES_THAN_OCSP_ANSWERS);
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
            if (usedResponses.size() != this.ocspRefs.size()) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        HAS_MORE_REFERENCES_THAN_OCSP_ANSWERS);
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            }
            if (usedCrls != this.crlRefs.size()) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        HAS_MORE_REFERENCES_THAN_OCSP_ANSWERS);
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            }
        }
    }

    /**
     * Verifica se a validação final é checada tanto com o OCSP quanto com a
     * lista de certificados revogados
     * @param endValidationIsEitherCheck Verdadeiro se a validação final for
     *            feita em ambos(CRL e OSCP)
     * @param endValidationIsCrlCheck Verdadeiro se a validação final for
     *            feita apenas na CRL
     * @param caValidationCanBeCrl Verdadeiro se a validação da autoridade
     *            certificadora admite a CRL
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos
     *             atributos da assinatura
     */
    private void verifyIfEndValidationIsEitherCheck(boolean endValidationIsEitherCheck, boolean endValidationIsCrlCheck,
            boolean caValidationCanBeCrl) throws SignatureAttributeException {
        if (endValidationCanBeCrl(endValidationIsEitherCheck, endValidationIsCrlCheck) && caValidationCanBeCrl) {
            int size = 0;
            size = this.checkEndCrl();
            size += this.checkCaCrl();
            if (size != this.crlRefs.size()) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        HAS_MORE_REFERENCES_THAN_OCSP_ANSWERS);
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            }
        }
    }

    /**
     * Verifica se toda a validação precisa ser checada com o serviço OCSP
     * @param endRevReq Indica as verificações mínimas que devem ser realizadas,
     *                  de acordo com a Política de Assinatura.
     * @param caValidationIsOcspCheck Verdadeiro se a validação da autoridade
     * certificadora é checado com serviço ocsp
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos
     * atributos da assinatura
     */
    private void verifyIfAllValidationMustBeOcspCheck(RevReq endRevReq, boolean caValidationIsOcspCheck) throws SignatureAttributeException {
        if (allValidationMustBeOcspCheck(caValidationIsOcspCheck, endValidationIsOcspCheck(endRevReq))) {
            Set<BasicOCSPResponse> usedResponses = new HashSet<BasicOCSPResponse>();
            usedResponses.addAll(this.checkEndOcsp());
            usedResponses.addAll(this.checkCaOcsp());
            if (usedResponses.size() != this.ocspRefs.size()) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        HAS_MORE_REFERENCES_THAN_OCSP_ANSWERS);
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            }
        }
    }

    /**
     * Verifica se a validação do certificado do assinante pode ser por CRL
     * @param endValidationIsEitherCheck Indica se a validação do certificado do assinante pode ser por OCSP ou CRL
     * @param endValidationIsCrlCheck Indica se a validação do certificado do assinante é por CRL
     * @return Indica se a validação do certificado do assinante pode ser por CRL
     */
    private boolean endValidationCanBeCrl(boolean endValidationIsEitherCheck, boolean endValidationIsCrlCheck) {
        return endValidationIsEitherCheck || endValidationIsCrlCheck;
    }

    /**
     * Verifica se a validação do certificado do assinante é por OCSP
     * @param endRevReq Requisições de validação de acordo com a política
     * @return Indica se a validação do certificado do assinante é por OCSP
     */
    private boolean endValidationIsOcspCheck(RevReq endRevReq) {
        return endRevReq.getEnuRevReq() == RevReq.EnuRevReq.OCSP_CHECK;
    }

    /**
     * Verifica se a validação deve ser OCSP para toda a cadeia de certificação
     * @param caValidationIsOcspCheck Indica se a validação da cadeia é por OCSP
     * @param endValidationIsOcspCheck Indica se a validação do certificado do assinante é por OCSP
     * @return Indica se a validação deve ser OCSP para toda a cadeia de certificação
     */
    private boolean allValidationMustBeOcspCheck(boolean caValidationIsOcspCheck, boolean endValidationIsOcspCheck) {
        boolean allValidationMustBeOcspCheck = caValidationIsOcspCheck && endValidationIsOcspCheck;
        return allValidationMustBeOcspCheck;
    }

    /**
     * Busca a resposta OCSP para os certificados no caminho de certificação
     * @return A resposta OCSP para os certificados no caminho de certificação
     * @throws SignatureAttributeException
     */
    @SuppressWarnings("unchecked")
    private Set<BasicOCSPResponse> checkCaOcsp() throws SignatureAttributeException {
        CertPath certPath = this.signatureVerifier.getSignerCertPath();
        List<X509Certificate> certificates = (List<X509Certificate>) certPath.getCertificates();
        List<X509Certificate> caCertificates = certificates.subList(1, certificates.size());
        Set<BasicOCSPResponse> obtainedResponses = new HashSet<BasicOCSPResponse>();
        for (X509Certificate caCertificate : caCertificates) {
            BasicOCSPResponse resp = null;
            try {
            	X509CertificateHolder caCert = new X509CertificateHolder(caCertificate.getEncoded());
                resp = this.getOcspRespFor(caCert);
            } catch (OCSPException ocspException) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        "Não foi possível obter a resposta OCSP", ocspException.getStackTrace());
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            } catch (IOException ioException) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        "Não foi possível obter a resposta ocsp", ioException.getStackTrace());
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            } catch (CertificateEncodingException certificateEncodingException) {
            	SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        "Não foi possível obter a resposta ocsp", certificateEncodingException.getStackTrace());
                signatureAttributeException.setCritical(this.isSigned());
			}
            obtainedResponses.add(resp);
        }
        for (BasicOCSPResponse obtainedResp : obtainedResponses) {
            if (!this.match(obtainedResp)) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException("Resposta OCSP faltando");
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            }
        }
        return obtainedResponses;
    }

    /**
     * Busca a resposta OCSP apenas para o certificado do assinante
     * @return A resposta OCSP para o certificado do assinante
     * @throws SignatureAttributeException
     */
    private Set<BasicOCSPResponse> checkEndOcsp() throws SignatureAttributeException {
        CertPath certPath = this.signatureVerifier.getSignerCertPath();
        BasicOCSPResponse ocspResponse = null;
        try {
        	X509CertificateHolder endCertificate = new X509CertificateHolder(certPath.getCertificates().get(0).getEncoded());
            ocspResponse = this.getOcspRespFor(endCertificate);
        } catch (OCSPException ocspException) {
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                    "Não foi possível obter a resposta ocsp", ocspException.getStackTrace());
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        } catch (IOException ioException) {
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                    "Não foi possível obter a resposta ocsp", ioException.getStackTrace());
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        } catch (CertificateEncodingException certificateEncodingException) {
        	SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                    "Não foi possível obter a resposta ocsp", certificateEncodingException.getStackTrace());
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
		}
        if (!this.match(ocspResponse)) {
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException("Referência a resposta OCSP faltando");
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        }
        return Collections.singleton(ocspResponse);
    }

    /**
     * Cria um {@link X509CRLSelector} que contém os certificados indicados pelo parâmetro
     * @param signerOnly Indica se apenas o certificado do assinante deve ser considerado
     * @return O objeto {@link X509CRLSelector} gerado
     */
    private X509CRLSelector crlSelectorFromCertPath(boolean signerOnly) {
        X509CRLSelector selector = new X509CRLSelector();
        CertPath certPath = this.signatureVerifier.getSignerCertPath();
        List<X509Certificate> certs = (List<X509Certificate>) certPath.getCertificates();
        List<X509Certificate> neededCerts = new ArrayList<>();

        if (signerOnly) {
            neededCerts.add(certs.get(0));
        } else {
            neededCerts.addAll(certs.subList(1, certs.size()));
        }

        for (X509Certificate c : neededCerts) {
            selector.addIssuer(c.getIssuerX500Principal());
        }

        return selector;
    }

    /**
     * Verifica se as referências à cada CRL da assinatura está presente no atributo
     * @param signerOnly Indica se apenas o certificado do assinante é necessário na assinatura
     * @return A quantidade de CRLs na assinatura
     * @throws SignatureAttributeException incongruência na quantidade de LCRs
     */
    private int checkCrls(boolean signerOnly) throws SignatureAttributeException {
        XadesSignatureComponent xsc = this.signatureVerifier.getXadesSignatureComponent();
        Time ref = this.signatureVerifier.getTimeReference();
        X509CRLSelector selector = crlSelectorFromCertPath(signerOnly);

        Set<X509CRL> crls = new HashSet<>(xsc.certificateValidation.getCRLs(selector, ref));
        for (X509CRL crl : xsc.getSignatureIdentityInformation().getCRLs(selector, ref)) {
            if (selector.match(crl) && crl.getNextUpdate().after(ref) && crl.getThisUpdate().before(ref)) {
                // remove old if new comes after, or never add the old one
                crls.removeIf(alreadyAdded ->
                        crl.getIssuerX500Principal().equals(alreadyAdded.getIssuerX500Principal())
                                && crl.getThisUpdate().after(alreadyAdded.getThisUpdate()));
                if (crls.stream().noneMatch(alreadyAdded ->
                        crl.getIssuerX500Principal().equals(alreadyAdded.getIssuerX500Principal()))) {
                    crls.add(crl);
                }
            }
        }

        for (X509CRL crl : crls) {
            if (!this.match(crl)) {
                SignatureAttributeException e = new SignatureAttributeException(
                        "Referência à LCR faltando.");
                e.setCritical(this.isSigned());
                throw e;
            }
        }

        if (crls.isEmpty()) {
            SignatureAttributeException e = new SignatureAttributeException(
                    "LCR referenciada não está presente");
            e.setCritical(this.isSigned());
            throw e;
        }

        return crls.size();
    }

    /**
     * Realiza o processo do método {@see checkCrls} considerando apenas o certificado do assinante
     * @return A quantidade de CRLs na assinatura
     * @throws SignatureAttributeException
     */
    private int checkEndCrl() throws SignatureAttributeException {
        return checkCrls(true);
    }

    /**
     * Realiza o processo do método {@see checkCrls} considerando toda a cadeia de certificação
     * @return A quantidade de CRLs na assinatura
     * @throws SignatureAttributeException
     */
    private int checkCaCrl() throws SignatureAttributeException {
        return checkCrls(false);
    }

    /**
     * Busca a resposta OCSP para o certificado dado
     * @param certificate O certificado
     * @return A resposta OCSP para o certificado
     * @throws OCSPException Exceção em caso de erro ao buscar a resposta
     * @throws IOException Exceção em caso de má formação da resposta
     */
    private BasicOCSPResponse getOcspRespFor(X509CertificateHolder certificate) throws OCSPException, IOException {
        BasicOCSPResponse result = null;
        Iterator<OCSPResp> i = this.signatureVerifier.getOcspList().iterator();
        while (i.hasNext() && result == null) {
            OCSPResp resp = i.next();
            BasicOCSPResp basicResp = (BasicOCSPResp) resp.getResponseObject();
            SingleResp[] responses = basicResp.getResponses();
            int j = 0;
            while (j < responses.length) {
                if (responses[j].getCertID().matchesIssuer(certificate, null)
                        && responses[j].getCertID().getSerialNumber().equals(certificate.getSerialNumber())) {
                    ASN1Sequence basicOCSPRespSequence = (ASN1Sequence) ASN1Sequence.fromByteArray(basicResp.getEncoded());
                    BasicOCSPResponse basicOCSPResponse = BasicOCSPResponse.getInstance(basicOCSPRespSequence);
                    result = basicOCSPResponse;
                }
            }
        }
        return result;
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
            document = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
        } catch (ParserConfigurationException e) {
            throw new SignatureAttributeException("Documento não pode ser construído", e.getStackTrace());
        }

        Element completeRevocationRefs = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:CompleteRevocationRefs");

        if (!this.crlRefs.isEmpty()) {
            Element crlRefs = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:CRLRefs");
            completeRevocationRefs.appendChild(crlRefs);
            for (CRLRefs ref : this.crlRefs) {
                Element crlRef = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:CRLRef");
                crlRefs.appendChild(crlRef);
                Element digestAlgAndValue = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:DigestAlgAndValue");
                crlRef.appendChild(digestAlgAndValue);

                Element digestMethod = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:DigestMethod");
                digestAlgAndValue.appendChild(digestMethod);
                digestMethod.setAttribute(ALGORITHM, ref.getAlgorithm());

                Element digestValue = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:DigestValue");
                digestAlgAndValue.appendChild(digestValue);
                digestValue.setTextContent(ref.getDigestValue());

                Element crlIdentifier = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:CRLIdentifier");
                crlRef.appendChild(crlIdentifier);

                Element issuer = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:Issuer");
                crlIdentifier.appendChild(issuer);

                Element issueTime = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:IssueTime");
                SimpleDateFormat dateFormatGmt = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
                dateFormatGmt.setTimeZone(TimeZone.getTimeZone("GMT"));
                issueTime.setTextContent(dateFormatGmt.format(ref.getDate()));
                crlIdentifier.appendChild(issueTime);

                Element number = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:Number");
                crlIdentifier.appendChild(number);
                number.setTextContent(ref.getCrlNumber().toString());

            }
        }

        if (!this.ocspRefs.isEmpty()) {
            Element ocspRefs = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:OCSPRefs");
            completeRevocationRefs.appendChild(ocspRefs);
            for (OCSPRefs ref : this.ocspRefs) {
                Element ocspRef = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:OCSPRef");
                ocspRefs.appendChild(ocspRef);

                Element ocspIdentifier = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:OCSPIdentifier");
                ocspRef.appendChild(ocspIdentifier);
                Element responderID = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:ResponderID");
                ocspIdentifier.appendChild(responderID);
                if (!ref.isKeyName()) {
                    Element byName = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:ByName");
                    responderID.appendChild(byName);
                    byName.setTextContent(ref.getResponderName());
                } else {
                    Element byKey = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:ByKey");
                    responderID.appendChild(byKey);
                    byKey.setTextContent(new String(Base64.encode(ref.getResponderKey())));
                }

                Element producedAt = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:ProducedAt");

                SimpleDateFormat dateFormatGmt = new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss");
                dateFormatGmt.setTimeZone(TimeZone.getTimeZone("GMT"));
                producedAt.setTextContent(dateFormatGmt.format(ref.getProducedAt()));
                ocspIdentifier.appendChild(producedAt);

                Element digestAlgAndValue = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:DigestAlgAndValue");
                ocspRef.appendChild(digestAlgAndValue);

                Element digestMethod = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:DigestMethod");
                digestMethod.setAttribute(ALGORITHM, ref.getAlgorithm());
                digestAlgAndValue.appendChild(digestMethod);

                Element digestValue = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:DigestValue");
                digestValue.setTextContent(ref.getDigestValue());
                digestAlgAndValue.appendChild(digestValue);

            }

        }

        return completeRevocationRefs;

        /*
         * CompleteRevocationRefsType completeRevocationRefsType = new
         * CompleteRevocationRefsType();
         * completeRevocationRefsType.setCRLRefs(this.crlRefs);
         * completeRevocationRefsType.setOCSPRefs(this.ocspRefs); Element
         * completeCertificatesRef; try { completeCertificatesRef =
         * Marshaller.marshallAttribute(this.getIdentifier(),
         * CompleteRevocationRefsType.class, completeRevocationRefsType,
         * NamespacePrefixMapperImp.XADES_NS); } catch (XmlProcessingException
         * xmlProcessingException) { throw new
         * SignatureAttributeException(xmlProcessingException.getMessage(),
         * xmlProcessingException.getStackTrace()); } return
         * completeCertificatesRef;
         */

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
     * Verifica se a CRL está presente ou não no atributo
     * @param crl A CRL
     * @return Indica se a CRL está presente no atributo
     * @throws SignatureAttributeException
     */
    @Override
    public boolean match(CRL crl) {
        boolean result = crl instanceof X509CRL;
        if (result) {
            try {
                X509CRL x509Crl = (X509CRL) crl;
                result = findIdentifier(x509Crl.getEncoded());
            } catch (CRLException crlException) {
                crlException.printStackTrace();
                result = false;
            } catch (SignatureAttributeException signatureAttributeException) {
                signatureAttributeException.printStackTrace();
                result = false;
            }
        }
        return result;
    }

    /**
     * Seleciona as respostas OCSP que são referênciadas pelo atributo
     * @param responses Lista de repostas OCSPs
     * @return Lista de respostas OCSP que são referênciadas pelo atributo
     * @throws SignatureAttributeException
     */
    public List<BasicOCSPResponse> selectOCSPResponses(List<BasicOCSPResponse> responses) throws SignatureAttributeException {
        List<BasicOCSPResponse> selectedResponses = new ArrayList<BasicOCSPResponse>();
        for (BasicOCSPResponse response : responses) {
            if (this.match(response))
                selectedResponses.add(response);
        }
        return selectedResponses;
    }

    /**
     * Verifica se a resposta OCSP está presente ou não no atributo
     * @param response A resposta OCSP
     * @return Indica se a resposta OCSP está presente no atributo
     * @throws SignatureAttributeException
     */
    public boolean match(BasicOCSPResponse response) throws SignatureAttributeException {
        boolean result = false;
        try {
            result = this.findIdentifier(response.getEncoded());
        } catch (IOException ioException) {

            throw new SignatureAttributeException(SignatureAttributeException.PROBLEMS_TO_DECODE, ioException.getStackTrace());
        }
        return result;
    }

    /**
     * Verifica se a lista de OCSPs e CRLs contém o objeto dado
     * @param encodedRevocationData Os bytes do objeto a ser procurado
     * @return Indica se a lista contém o objeto
     * @throws SignatureAttributeException
     */
    private boolean findIdentifier(byte[] encodedRevocationData) throws SignatureAttributeException {
        boolean result = false;
        try {
            MessageDigest digester = MessageDigest.getInstance(AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(this.algorithm));
            byte[] obtainedHash = digester.digest(encodedRevocationData);
            String obtainedHashBase64 = new String(Base64.encode(obtainedHash));
            result = this.crlAndOcspIdSet.contains(obtainedHashBase64);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new SignatureAttributeException(SignatureAttributeException.NO_SUCH_ALGORITHM, noSuchAlgorithmException.getStackTrace());
        }
        return result;
    }

    /**
     * Construtor usado para clonar o objeto
     */
    private CompleteRevocationRefs() {
    }

    /**
     * Retorna um objeto identico à instância para qual a mensagem foi enviada.
     * As alterações feitas no objeto retornado não afetam a instância antes
     * mencionada.
     */
    @Override
    public CompleteRevocationRefs clone() {
        CompleteRevocationRefs completeRevocationRefs = new CompleteRevocationRefs();
        completeRevocationRefs.algorithm = this.algorithm;
        completeRevocationRefs.crlRefs = new ArrayList<CRLRefs>(this.crlRefs);
        completeRevocationRefs.crlRefs.addAll(this.crlRefs);
        completeRevocationRefs.ocspRefs = new ArrayList<OCSPRefs>(this.ocspRefs);
        completeRevocationRefs.ocspRefs.addAll(this.ocspRefs);
        completeRevocationRefs.crlAndOcspIdSet = new HashSet<String>(this.crlAndOcspIdSet);
        return completeRevocationRefs;
    }

    /**
     * Retorna a lista de referências CRL
     * @return A lista de referências de CRL
     */
    public List<CRLRefs> getCrlRefs() {
        return new ArrayList<CRLRefs>(this.crlRefs);
    }

    /**
     * Retorna a lista de referências OCSP
     * @return A lista de referências OCSP
     */
    public List<OCSPRefs> getOcspRefs() {
        if (this.ocspRefs == null) {
            return new ArrayList<>();
        }
        return new ArrayList<OCSPRefs>(this.ocspRefs);
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
