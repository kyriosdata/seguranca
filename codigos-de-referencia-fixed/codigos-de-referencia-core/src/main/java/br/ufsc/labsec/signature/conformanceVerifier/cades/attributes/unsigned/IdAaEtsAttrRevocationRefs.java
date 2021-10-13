/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.sql.Time;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.esf.CrlIdentifier;
import org.bouncycastle.asn1.esf.CrlListID;
import org.bouncycastle.asn1.esf.CrlOcspRef;
import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.esf.OcspIdentifier;
import org.bouncycastle.asn1.esf.OcspListID;
import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.AttributeCertificateInfo;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.util.encoders.Base64;

import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaEtsSignerAttr;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;


/**
 * 
 * O atributo IdAaEtsAttrRevocationRefs guarda referências de todas as CRLs ou
 * respostas OCSPs usadas na validação do certificado de atributo.
 * 
 * Oid e esquema do atributo attribute-revocation-references retirado do
 * documento ETSI TS 101 733 V1.8.1
 * 
 * <pre>
 * 
 * id-aa-ets-attrRevocationRefs OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 45}
 * 
 * AttributeRevocationRefs ::= SEQUENCE OF CrlOcspRef
 * 
 * CrlOcspRef ::= SEQUENCE {
 * 	crlids 	 [0] CRLListID OPTIONAL,
 * 	ocspids  [1] OcspListID OPTIONAL,
 * 	otherRev [2] OtherRevRefs OPTIONAL
 * }
 * 
 * CRLListID ::= SEQUENCE {
 * 	crls     SEQUENCE OF CrlValidatedID }
 * 
 * CrlValidatedID ::= SEQUENCE {
 * 	crlHash           OtherHash,
 *     	crlIdentifier     CrlIdentifier OPTIONAL }
 * 
 * OtherHash ::= CHOICE {
 * 	sha1Hash 	OtherHashValue, -- This contains a SHA-1 hash
 * 	otherHash 	OtherHashAlgAndValue}
 * 
 * OtherHashAlgAndValue ::= SEQUENCE {
 * 	hashAlgorithm 	AlgorithmIdentifier,
 * 	hashValue	OtherHashValue }
 * 
 * OtherHashValue ::= OCTET STRING
 * 
 * CrlIdentifier ::= SEQUENCE {
 * 	crlissuer          Name,
 * 	crlIssuedTime      UTCTime,
 * 	crlNumber          INTEGER OPTIONAL }
 * 
 * OcspListID ::= SEQUENCE {
 * 	ocspResponses     SEQUENCE OF OcspResponsesID }
 * 
 * OcspResponsesID ::= SEQUENCE {
 * 	ocspIdentifier     OcspIdentifier,
 * 	ocspRepHash        OtherHash OPTIONAL }
 * 
 * OcspIdentifier ::= SEQUENCE {
 * 	ocspResponderID     ResponderID, -- As in OCSP response data
 * 	producedAt          GeneralizedTime -- As in OCSP response data
 * }
 * 
 * OtherRevRefs ::= SEQUENCE {
 * 	otherRevRefType     OtherRevRefType,
 * 	otherRevRefs        ANY DEFINED BY otherRevRefType
 * }
 * 
 * OtherRevRefType ::= OBJECT IDENTIFIER
 * </pre>
 */
public class IdAaEtsAttrRevocationRefs implements SignatureAttribute {

    public static final String IDENTIFIER = "1.2.840.113549.1.9.16.2.45";
    /**
     * Referência de CRLs e respostas OCSP
     */
    private CrlOcspRef crlOcspRef;
    /**
     * Objeto de verificador
     */
    private AbstractVerifier signatureVerifier;
    /**
     * Algoritmo de cálculo de hash
     */
    private String algorithm;
    /**
     * Conjunto de hashes de CRLs
     */
    private Set<String> crlHashsSet;
    /**
     * Conjunto de IDs das respostas OCSP
     */
    private Set<String> ocspIdsSet;

    /**
     * <p>
     * Deve-se utilizar este construtor no momento de validação do atributo. O
     * parâmetro <code> index </code> deve ser usado no caso em que há mais de
     * um atributo do mesmo tipo. Caso contrário, ele deve ser zero.
     * </p>
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * @throws SignatureAttributeException
     */
    public IdAaEtsAttrRevocationRefs(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        this.signatureVerifier = signatureVerifier;
        Attribute genericEncoded = signatureVerifier.getSignature().getEncodedAttribute(IDENTIFIER, index);
        this.decode(genericEncoded);
    }

    /**
     * 
     * Cria um atributo que irá referenciar as LCRs passadas na lista. Na
     * referência será usado um algoritmo de hash, o identificador do mesmo deve
     * ser passado para <code>digestAlgorithm</code>
     * @param crlList A lista de CRLs
     * @param algorithm O algoritmo de hash
     * @throws SignatureAttributeException
     */
    public IdAaEtsAttrRevocationRefs(List<X509CRL> crlList, String algorithm) throws SignatureAttributeException {
        this.algorithm = algorithm;
        CrlListID crlListId = getCrlListId(crlList, algorithm);
        this.crlOcspRef = new CrlOcspRef(crlListId, null, null);
    }

    /**
     * Cria um atributo que irá referenciar as respostas OCSP passadas na lista.
     * Na referência será usado um algoritmo de hash, o identificador do mesmo
     * deve ser passado para <code>digestAlgorithm</code>
     * @param algorithm O algoritmo de hash
     * @param ocspList A lista de respostas OCSP
     * @throws SignatureAttributeException
     */
    public IdAaEtsAttrRevocationRefs(String algorithm, List<BasicOCSPResponse> ocspList) throws SignatureAttributeException {
        this.algorithm = algorithm;
        OcspListID ocspListId = getOcspListId(ocspList);
        this.crlOcspRef = new CrlOcspRef(null, ocspListId, null);
    }

    /**
     * Cria um atributo que irá referenciar as respostas OCSP e LCRs passadas na lista.
     * Na referência será usado um algoritmo de hash, o identificador do mesmo 
     * deve ser passado para <code>digestAlgorithm</code>
     * @param crlList A lista de CRLs
     * @param ocspList A lista de respostas OCSP
     * @param algorithm O algoritmo de hash
     * @throws SignatureAttributeException
     */
    public IdAaEtsAttrRevocationRefs(List<X509CRL> crlList, List<BasicOCSPResponse> ocspList, String algorithm)
            throws SignatureAttributeException {
        this.algorithm = algorithm;
        CrlListID crlListId = this.getCrlListId(crlList, algorithm);
        OcspListID ocspListId = this.getOcspListId(ocspList);
        this.crlOcspRef = new CrlOcspRef(crlListId, ocspListId, null);
    }

    /**
     * Constrói um objeto {@link IdAaEtsAttrRevocationRefs}
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException
     */
    public IdAaEtsAttrRevocationRefs(Attribute attributeEncoded) throws SignatureAttributeException {
        decode(attributeEncoded);
    }

    /**
     * Constrói um objeto {@link IdAaEtsAttrRevocationRefs}
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException
     */
    private void decode(Attribute attributeEncoded) throws SignatureAttributeException {
        DERSet AttrRevocationRefsSet = null;
        AttrRevocationRefsSet = (DERSet) attributeEncoded.getAttrValues();
        DERSequence crlOcspRefSequence = (DERSequence) AttrRevocationRefsSet.getObjectAt(0);
        this.crlOcspRef = CrlOcspRef.getInstance(crlOcspRefSequence);
        CrlListID crlListId = this.crlOcspRef.getCrlids();
        OcspListID ocspListId = this.crlOcspRef.getOcspids();
        AlgorithmIdentifier hashAlgorithmId = null;
        this.crlHashsSet = new HashSet<String>();
        if (crlListId != null) {
            CrlValidatedID[] crlValidatedIds = crlListId.getCrls();
            hashAlgorithmId = crlValidatedIds[0].getCrlHash().getHashAlgorithm();
            for (CrlValidatedID crlValidatedId : crlValidatedIds) {
                crlHashsSet.add(new String(Base64.encode(crlValidatedId.getCrlHash().getHashValue())));
            }
        }
        this.ocspIdsSet = new HashSet<String>();
        if (ocspListId != null) {
            OcspResponsesID[] ocspResponsesIds = ocspListId.getOcspResponses();
            hashAlgorithmId = ocspResponsesIds[0].getOcspRepHash().getHashAlgorithm();
            for (OcspResponsesID ocspResponsesId : ocspResponsesIds) {
                ocspIdsSet.add(new String(Base64.encode(ocspResponsesId.getOcspRepHash().getHashValue())));
            }
        }
        this.algorithm = hashAlgorithmId.getAlgorithm().getId();
    }

    /**
     * Cria um objeto {@link CrlListID} com as informações das CRLs
     * @param crlList A lista de CRLs
     * @param algorithm O algoritmo de hash
     * @return O objeto {@link CrlListID} criado
     * @throws SignatureAttributeException
     */
    private CrlListID getCrlListId(List<X509CRL> crlList, String algorithm) throws SignatureAttributeException {
        CrlListID crlListId = null;
        if (crlList != null && !crlList.isEmpty()) {
            List<CrlValidatedID> crlValidateIdList = this.generateCrlValidateIdList(crlList, algorithm);
            crlListId = new CrlListID(crlValidateIdList.toArray(new CrlValidatedID[0]));
        } else {
            throw new SignatureAttributeException("A lista de CRLs não pode ser nula ou vazia.");
        }
        return crlListId;
    }

    /**
     * Cria um objeto {@link OcspListID} com as informações das respostas OCSP
     * @param ocspList A lista de respostas OCSP
     * @return O objeto {@link OcspListID} criado
     * @throws SignatureAttributeException
     */
    private OcspListID getOcspListId(List<BasicOCSPResponse> ocspList) throws SignatureAttributeException {
        OcspListID ocspListId = null;
        if (ocspList != null && !ocspList.isEmpty()) {
            List<OcspResponsesID> ocspResponsesIdList;
            try {
                ocspResponsesIdList = this.generateOcspResponsesIdList(ocspList);
            } catch (IOException ioException) {
                throw new SignatureAttributeException(ioException);
            }
            ocspListId = new OcspListID(ocspResponsesIdList.toArray(new OcspResponsesID[0]));
        } else {
            throw new SignatureAttributeException("A lista de respotas OCSP não pode ser nula ou vazia.");
        }
        return ocspListId;
    }

    /**
     * Cria uma lista de {@link OcspResponsesID}, que engloba o identificador das respostas OCSP
     * e seu valor de OtherHash
     * @param ocspList A lista de respostas OCSP
     * @return A lista de {@link OcspResponsesID} criada
     * @throws SignatureAttributeException
     * @throws IOException
     */
    private List<OcspResponsesID> generateOcspResponsesIdList(List<BasicOCSPResponse> ocspList) throws SignatureAttributeException,
        IOException {
        List<OcspResponsesID> ocspResponsesIdList = new ArrayList<OcspResponsesID>();
        for (BasicOCSPResponse basicOcspResponse : ocspList) {
            OtherHash otherHash = this.getOtherHash(basicOcspResponse.getEncoded());
            OcspIdentifier ocspIdentifier = new OcspIdentifier(basicOcspResponse.getTbsResponseData().getResponderID(), basicOcspResponse
                    .getTbsResponseData().getProducedAt());
            ocspResponsesIdList.add(new OcspResponsesID(ocspIdentifier, otherHash));
        }
        return ocspResponsesIdList;
    }

    /**
     * Cria uma lista de {@link CrlValidatedID}, que engloba o identificador da CRL
     * e seu valor de OtherHash
     * @param crlList A lista de CRLs
     * @param algorithm O algoritmo de hash
     * @return A lista de {@link CrlValidatedID} criada
     * @throws SignatureAttributeException
     */
    private List<CrlValidatedID> generateCrlValidateIdList(List<X509CRL> crlList, String algorithm) throws SignatureAttributeException {
        List<CrlValidatedID> crlValidateIdList = new ArrayList<CrlValidatedID>();
        for (X509CRL x509crl : crlList) {
            byte[] crlBytes = null;
            try {
                crlBytes = x509crl.getEncoded();
            } catch (CRLException crlException) {
                throw new SignatureAttributeException(crlException);
            }
            OtherHash otherHash = this.getOtherHash(crlBytes);
            X500Name x500name = new X500Name(x509crl.getIssuerX500Principal().toString());
            Time time = new Time(x509crl.getThisUpdate().getTime());
            CrlIdentifier crlIdentifier = new CrlIdentifier(x500name, new DERUTCTime(time));
            crlValidateIdList.add(new CrlValidatedID(otherHash, crlIdentifier));
        }
        return crlValidateIdList;
    }

    /**
     * Calcula o valor de OtherHash dos bytes dados
     * @param data Os bytes a serem usados no cálculo
     * @return O valor de OtherHash dos bytes dados
     * @throws SignatureAttributeException
     */
    private OtherHash getOtherHash(byte[] data) throws SignatureAttributeException {
        OtherHash otherHash = null;
        String algorithmName = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(this.algorithm);
        if (algorithmName == null) {
            throw new SignatureAttributeException(SignatureAttributeException.NO_SUCH_ALGORITHM);
        }
        MessageDigest digester = null;
        try {
            digester = MessageDigest.getInstance(algorithmName);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new SignatureAttributeException(noSuchAlgorithmException.getMessage(), noSuchAlgorithmException.getStackTrace());
        }
        byte[] hash = null;
        hash = digester.digest(data);
        if (algorithmName.equals("sha-1")) {
            otherHash = new OtherHash(hash);
        } else {
            AlgorithmIdentifier algorithmIdentifier = AlgorithmIdentifier.getInstance(this.algorithm);
            ASN1OctetString hashValue = new DEROctetString(hash);
            OtherHashAlgAndValue hashAlgAndValue = new OtherHashAlgAndValue(algorithmIdentifier, hashValue);
            otherHash = new OtherHash(hashAlgAndValue);
        }
        return otherHash;
    }

    /**
     * Retorna a referência
     * @return A referência de CRLs e OCSP
     */
    public CrlOcspRef getCrlOcspRef() {
        return this.crlOcspRef;
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return IdAaEtsAttrRevocationRefs.IDENTIFIER;
    }

    /**
     * Valida o atributo de acordo com suas regras específicas
     * @throws SignatureAttributeException
     */
    @Override
    public void validate() throws SignatureAttributeException, IOException {
        CadesSignature signature = this.signatureVerifier.getSignature();
        int numberOfAttrRevRefsAttributes = 0;
        for (String identifier : signature.getAttributeList()) {
            if (identifier.equals(this.getIdentifier()))
                numberOfAttrRevRefsAttributes++;
        }
        if (numberOfAttrRevRefsAttributes > 1) {
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                    "O atributo é invalido pois possue mais de uma instância na assinatura.");
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        }
        boolean hasAttributeCertificate = false;
        Iterator<String> attributeListIterator = signature.getAttributeList().iterator();
        while (attributeListIterator.hasNext() && !hasAttributeCertificate) {
            if (attributeListIterator.next().equals(IdAaEtsSignerAttr.IDENTIFIER))
                hasAttributeCertificate = true;
        }
        if (!hasAttributeCertificate) {
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                    "Não foi possível obter o Attribute Certificate da assinatura.");
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        }
        IdAaEtsSignerAttr signerAttribute = new IdAaEtsSignerAttr(this.signatureVerifier, 0);
        AttributeCertificate attributeCertificate = signerAttribute.getAttributeCertificate();
        if (attributeCertificate == null) {
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                    "A assinatura não contém o Attribute Certificate.");
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        }
        AttributeCertificateInfo attrCertificateInfo = attributeCertificate.getAcinfo();
        Extensions extensions = attrCertificateInfo.getExtensions();
        if (extensions != null) {
            String noRevocationAvailableOid = "2.5.29.56";
            ASN1ObjectIdentifier noRevocationAvailableIdentifier = new ASN1ObjectIdentifier(noRevocationAvailableOid);
            Extension noRevocationAvailable = extensions.getExtension(noRevocationAvailableIdentifier);
            if (noRevocationAvailable != null) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                        "O Attribute Certificate dessa assinatura não é revogável.");
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            }
        }
    }

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato ASN.1
     */
    @Override
    public Attribute getEncoded() throws SignatureAttributeException {
        DERSet setCrlOcspRef = new DERSet(this.crlOcspRef);
        Attribute revocationRefsAttribute = new Attribute(new ASN1ObjectIdentifier(this.getIdentifier()), setCrlOcspRef);
        return revocationRefsAttribute;
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
     * Verifica se o atributo deve ter apenas uma instância na assinatura
     * @return Indica se o atributo deve ter apenas uma instância na assinatura
     */
    @Override
    public boolean isUnique() {

        return true;
    }
}
