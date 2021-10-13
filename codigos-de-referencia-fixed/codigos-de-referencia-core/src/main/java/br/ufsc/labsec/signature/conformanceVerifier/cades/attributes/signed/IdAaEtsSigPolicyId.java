/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed;

import java.security.MessageDigest;
import java.util.Enumeration;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.esf.SigPolicyQualifierInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * O atributo signature policy identifier representa o identificador da política
 * de assinatura.
 * <p>
 * Este atributo é obrigatório para todas as políticas do Padrão Brasileiro de
 * Assinatura Digital.
 * <p>
 * Mais informações: http://www.ietf.org/rfc/rfc3126.txt
 * <p>
 * 
 * Oid e esquema do atributo id-aa-ets-sigPolicyId retirado da RFC 3126:
 * 
 * <pre>
 * id-aa-ets-sigPolicyId OBJECT IDENTIFIER ::= { iso(1)
 * member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
 * smime(16) id-aa(2) 15 }
 * 
 * SignaturePolicyIdentifier ::= CHOICE{
 * SignaturePolicyId SignaturePolicyId,
 * SignaturePolicyImplied SignaturePolicyImplied }
 * 
 * SignaturePolicyId ::= SEQUENCE {
 * sigPolicyIdentifier SigPolicyId,
 * sigPolicyHash SigPolicyHash,
 * sigPolicyQualifiers SEQUENCE SIZE (1..MAX) OF
 * SigPolicyQualifierInfo OPTIONAL
 * }
 * 
 * SignaturePolicyImplied ::= NULL
 * 
 * SigPolicyId ::= OBJECT IDENTIFIER
 * 
 * SigPolicyHash ::= OtherHashAlgAndValue
 * 
 * SigPolicyQualifierInfo ::= SEQUENCE {
 * sigPolicyQualifierId SigPolicyQualifierId,
 * sigQualifier ANY DEFINED BY sigPolicyQualifierId
 * </pre>
 * 
 * }
 */
public class IdAaEtsSigPolicyId implements SignatureAttribute {

    public static final String IDENTIFIER = PKCSObjectIdentifiers.id_aa_ets_sigPolicyId.toString();
    /**
     * O identificador da política de assinatura
     */
    private String sigPolicyId;
    /**
     * O método utilizado para o cálculo de hash
     */
    private String digestMethodId;
    /**
     * A URL da política
     */
    private String sigPolicyUrl;
    /**
     * O valor de hash da PA
     */
    private byte[] sigPolicyHash;
    /**
     * Objeto de verificador
     */
    private AbstractVerifier signatureVerifier;

    /**
     * Deve-se utilizar este construtor no momento de validação do atributo.
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Este índide deve ser 0 para este atributo
     * @throws SignatureAttributeException
     */
    public IdAaEtsSigPolicyId(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        Attribute attributeEncoded = signatureVerifier.getSignature().getEncodedAttribute(this.getIdentifier(), index);
        decode(attributeEncoded);
        this.signatureVerifier = signatureVerifier;
    }

    /**
     * Cria o atributo id-aa-ets-sigPolicyId a partir dos parâmetros necessários
     * para a criação do atributo.
     * 
     * @param sigPolicyId Identifiador da política de assinatura
     * @param digestMethodId Identifiador do algoritmo de resumo criptográfico usado
     *            para gerar o resumo criptográfico da assinatura
     * @param policyHash Valor do resumo criptográfico obtido da política
     *            assinatura
     * @param policyUrl URL que indica onde a politica de assinatura pode ser
     *            encontrada
     */
    public IdAaEtsSigPolicyId(String sigPolicyId, String digestMethodId, byte[] policyHash, String policyUrl) {
        this.setSigPolicyId(sigPolicyId);
        this.setDigestMethodId(digestMethodId);
        this.setSigPolicyHash(policyHash);
        if (policyUrl != null) {
            this.setSigPolicyUrl(policyUrl);
        }
    }

    /**
     * Constrói um objeto {@link IdAaEtsSigPolicyId}
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException
     */
    public IdAaEtsSigPolicyId(Attribute attributeEncoded) throws SignatureAttributeException {
        decode(attributeEncoded);
    }

    /**
     * Constrói um objeto {@link IdAaEtsSigPolicyId}
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException
     */
    private void decode(Attribute attributeEncoded) throws SignatureAttributeException {
    	ASN1Encodable derSigPolicyEncodable = null;
        derSigPolicyEncodable = attributeEncoded.getAttrValues();
        ASN1Set signaturePolicyIdentifierSet = (ASN1Set) derSigPolicyEncodable;
        ASN1Sequence sigPolicyIdSequence = (ASN1Sequence) signaturePolicyIdentifierSet.getObjectAt(0);
        // pega o valor do identificador da política
        this.sigPolicyId = sigPolicyIdSequence.getObjectAt(0).toString();
        ASN1Sequence otherHashAlgAndValue = (ASN1Sequence) sigPolicyIdSequence.getObjectAt(1);
        // oid do hash
        if (otherHashAlgAndValue.getObjectAt(0) instanceof ASN1Sequence) {
            this.digestMethodId = otherHashAlgAndValue.getObjectAt(0).toString();
        } else if (otherHashAlgAndValue.getObjectAt(0) instanceof AlgorithmIdentifier) {
            AlgorithmIdentifier hashAlgorithmIdentifier = (AlgorithmIdentifier) otherHashAlgAndValue.getObjectAt(0);
            this.digestMethodId = hashAlgorithmIdentifier.getAlgorithm().getId();
        }
        // byte do hash
        ASN1OctetString hashValue = (ASN1OctetString) otherHashAlgAndValue.getObjectAt(1);
        this.sigPolicyHash = hashValue.getOctets();
        // é necessário iterar sobre os sigPolicyQualifierInfo por ser uma lista
        if (sigPolicyIdSequence.size() == 3) {
            ASN1Sequence sigPolicyQualifierInfoSequence = (ASN1Sequence) sigPolicyIdSequence.getObjectAt(2);
            Enumeration<?> qualifierInfoEnumeration = sigPolicyQualifierInfoSequence.getObjects();
            Object sigPolicyQualifierActual;
            boolean found = false;
            while (qualifierInfoEnumeration.hasMoreElements() && !found) {
                sigPolicyQualifierActual = qualifierInfoEnumeration.nextElement();
                if (sigPolicyQualifierActual instanceof ASN1Sequence) {
                    ASN1Sequence sigPolicyQualifierSequence = (ASN1Sequence) sigPolicyQualifierActual;
                    if (sigPolicyQualifierSequence.getObjectAt(0).equals(PKCSObjectIdentifiers.id_spq_ets_uri)) {
                        this.sigPolicyUrl = sigPolicyQualifierSequence.getObjectAt(1).toString();
                        // encontrou a uri da política
                        found = true;
                    }
                } else {
                    SigPolicyQualifierInfo sigPolicyQualifierInfo = (SigPolicyQualifierInfo) sigPolicyQualifierActual;
                    if (sigPolicyQualifierInfo.getSigPolicyQualifierId().getId().compareTo(PKCSObjectIdentifiers.id_spq_ets_uri.getId()) == 0) {
                        this.sigPolicyUrl = sigPolicyQualifierInfo.getSigQualifier().toString();
                        found = true;
                    }
                }
            }
        }
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    public String getIdentifier() {
        return IdAaEtsSigPolicyId.IDENTIFIER;
    }

    /**
     * Valida o atributo de acordo com suas regras específicas
     * @throws SignatureAttributeException
     */
    public void validate() throws SignatureAttributeException {
        SignaturePolicyInterface expectedSignaturePolicy = this.signatureVerifier.getSignaturePolicy();
        byte[] expectedSignaturePolicyHash = expectedSignaturePolicy.getSignPolicyHash();
        byte[] actualSignaturePolicyHash = this.sigPolicyHash;

        if (expectedSignaturePolicyHash.length != 0) {
            boolean isEqual = MessageDigest.isEqual(expectedSignaturePolicyHash, actualSignaturePolicyHash);

            if (!isEqual)
                throw new SignatureAttributeException(
                        "Inconsistência no IdAaEtsSigPolicyIdentifier: os resumos criptográficos do atributo e da PA não são os mesmos.");
        } else {
            throw new SignatureAttributeException(
                   SignatureAttributeException.INVALID_PA_OID);
        }

    }

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato ASN1
     */
    public Attribute getEncoded() {
        // SignaturePolicyIdentifier
        // SignaturePolicyId
        ASN1EncodableVector signaturePolicyIdVector = new ASN1EncodableVector();
        // sisPolicyID
        ASN1ObjectIdentifier sigPolicyIdOid = new ASN1ObjectIdentifier(this.sigPolicyId);
        signaturePolicyIdVector.add(sigPolicyIdOid);
        // sigPolicyHash
        ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(this.digestMethodId);
        AlgorithmIdentifier hashAlgorithmIdentifier = new AlgorithmIdentifier(oid);
        DEROctetString hashOctetString = new DEROctetString(this.sigPolicyHash);
        ASN1EncodableVector sigPolicyHashOtherHashAndAlgVector = new ASN1EncodableVector();
        sigPolicyHashOtherHashAndAlgVector.add(hashAlgorithmIdentifier);
        sigPolicyHashOtherHashAndAlgVector.add(hashOctetString);
        DERSequence sigPolicyHashOtherHashAndAlgSequence = new DERSequence(sigPolicyHashOtherHashAndAlgVector);
        signaturePolicyIdVector.add(sigPolicyHashOtherHashAndAlgSequence);
        if (this.sigPolicyUrl != null) {
            // sigPolicyQualifiers
            SigPolicyQualifierInfo sigPolicyQualifierSPUriVector = new SigPolicyQualifierInfo(PKCSObjectIdentifiers.id_spq_ets_uri,
                    new DERIA5String(this.sigPolicyUrl));
            // adiciona atributos do SignaturePolicyId
            DERSequence sigPolicyQualifierSPUriSequence = new DERSequence(sigPolicyQualifierSPUriVector);
            signaturePolicyIdVector.add(sigPolicyQualifierSPUriSequence);
        }

        // transformação de asn1EncodableVector -> Attribute -> GenericEncoding
        Attribute signaturePolicyIdentifierAttribute = new Attribute(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId, new DERSet(
                new DERSequence(signaturePolicyIdVector)));
        return signaturePolicyIdentifierAttribute;
    }

    /**
     * Retorna o identificador da política
     * @return O identificador da política
     */
    public String getSignaturePolicyId() {
        return this.sigPolicyId;
    }

    /**
     * Atribue o OID da politica de assinatura para o atributo
     * @param sigPolicyId O OID da politica de assinatura
     */
    public void setSigPolicyId(String sigPolicyId) {
        this.sigPolicyId = sigPolicyId;
    }

    /**
     * Retorna o indicador de qual foi o algoritmo de resumo criptográfico usado
     * para gerar o resumo criptográfico da assinatura.
     * @return O OID do algoritmo de resumo criptográfico usado para gerar o
     *         resumo criptográfico da assinatura
     */
    public String getDigestMethodId() {
        return this.digestMethodId;
    }

    /**
     * Atribue o indicador de qual foi o algoritmo de hash usado para tirar o
     * hash da assinatura
     * @param digestMethodId O OID do algoritmo de resumo criptográfico usado
     *            para gerar o resumo criptográfico da assinatura
     */
    public void setDigestMethodId(String digestMethodId) {
        this.digestMethodId = digestMethodId;
    }

    /**
     * Obtém a URL que indica onde a PA (Politica de Assinatura) pode ser
     * encontrada
     * @return URL identificadora da PA
     */
    public String getSigPolicyUrl() {
        return this.sigPolicyUrl;
    }

    /**
     * Atribue a URL que indica onde a PA (Politica de Assinatura) pode ser
     * encontrada
     * @param sigPolicyUrl URL identificadora da PA.
     */
    public void setSigPolicyUrl(String sigPolicyUrl) {
        this.sigPolicyUrl = sigPolicyUrl;
    }

    /**
     * Retorna o valor hash obtido da assinatura
     * @return O valor hash obtido da assinatura
     */
    public byte[] getSigPolicyHash() {
        return this.sigPolicyHash;
    }

    /**
     * Atribue o valor hash obtido da PA (Política de Assinatura)
     * @param sigPolicyHash O valor do resumo criptográfico obtido da PA
     */
    public void setSigPolicyHash(byte[] sigPolicyHash) {
        this.sigPolicyHash = sigPolicyHash;
    }

    /**
     * Informa se o atributo é assinado.
     * @return Indica se o atributo é assinado
     */
    public boolean isSigned() {
        return true;
    }

    /**
     * Retorna a URL da LPA
     * @return {@link String}
     */
    public String getLpaUrl() {
        return getSigPolicyUrl();
    }

    /**
     * Retorna o valor de hash da política
     * @return O valor de hash da política
     */
    public String getSignaturePolicyHashValue() {
        return new String(this.sigPolicyHash);
    }

    /**
     * Verifica se o atributo deve ter apenas uma instância na assinatura
     * @return Indica se o atributo deve ter apenas uma instância na assinatura
     */
    public boolean isUnique() {

        return true;
    }
}
