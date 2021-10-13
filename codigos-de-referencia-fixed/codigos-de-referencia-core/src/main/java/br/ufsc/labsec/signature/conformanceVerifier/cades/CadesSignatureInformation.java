/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.esf.SigPolicyQualifierInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.CounterSignatureInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsArchiveTimeStampV2;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsAttrCertificateRefs;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsAttrRevocationRefs;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdCounterSignature;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.CounterSignatureException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.UniqueAttributeException;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import br.ufsc.labsec.signature.exceptions.VerificationException;

/**
 * Esta classe representa tanto uma assinatura quanto uma contra-assinatura CAdES.
 * Implementa {@link CmsParent} e {@link Signature}.
 */
public class CadesSignatureInformation implements CmsParent, Signature {

    /**
     * Informações do assinante
     */
    protected SignerInformation signerInformation;
    /**
     * Indica se a assinatura possui conteúdo destacado
     */
    protected boolean isDetached;
    /**
     * Objeto CMS ao qual o assinante pertence
     */
    private CmsParent parent;

    /**
     * Constrói um {@link CadesSignatureInformation}
     * @param signerInformation Objeto que encapsula uma assinatura
     * @param isDetached Indica se a assinatura é destacada
     * @param parent Objeto CMS ao qual o signerInformation pertence
     */
    protected CadesSignatureInformation(SignerInformation signerInformation, boolean isDetached, CmsParent parent) {
        this.signerInformation = signerInformation;
        this.isDetached = isDetached;
        this.parent = parent;
    }

    /**
     * Atribue o CMS ao qual o assinante pertence
     * @param parent O objeto CMS
     */
    public void setParent(CmsParent parent) {
        this.parent = parent;
    }

    /**
     * Retorna a lista de atributos assinados e não-assinados da assinatura
     * @return A lista de atributos assinados e não-assinados da assinatura
     */
    public List<String> getAttributeList() {
        List<String> attributeOidList = new ArrayList<String>();
        ASN1EncodableVector signedAttributeTableVector;
        ASN1EncodableVector unsignedAttributeTableVector;
        AttributeTable signedAttributeTable = this.signerInformation.getSignedAttributes();
        if (signedAttributeTable != null) {
            signedAttributeTableVector = signedAttributeTable.toASN1EncodableVector();
            for (int i = 0; i < signedAttributeTableVector.size(); i++) {
                Attribute signedAttribute = (Attribute) signedAttributeTableVector.get(i);
                attributeOidList.add(signedAttribute.getAttrType().getId());
            }
            AttributeTable unsignedAttributeTable = this.signerInformation.getUnsignedAttributes();
            if (unsignedAttributeTable != null) {
                unsignedAttributeTableVector = unsignedAttributeTable.toASN1EncodableVector();
                for (int i = 0; i < unsignedAttributeTableVector.size(); i++) {
                    Attribute unsignedAttribute = (Attribute) unsignedAttributeTableVector.get(i);
                    attributeOidList.add(unsignedAttribute.getAttrType().getId());
                }
            }
        }
        return attributeOidList;
    }

    /**
     * Retorna um objeto do atributo desejado
     * @param attributeId O identificador do atributo
     * @param index Índice do atributo
     * @return Um objeto do atributo desejado
     */
    public Attribute getEncodedAttribute(String attributeId, Integer index) throws SignatureAttributeNotFoundException {
        if (index < 0) {
            throw new SignatureAttributeNotFoundException(SignatureAttributeNotFoundException.INDEX_OUT_OF_BOUNDS);
        }
        ASN1EncodableVector attributeVector = this.signerInformation.getSignedAttributes().getAll(new ASN1ObjectIdentifier(attributeId));
        if (attributeVector.size() == 0) {
            AttributeTable table = this.signerInformation.getUnsignedAttributes();
            if (table == null) {
                throw new SignatureAttributeNotFoundException(SignatureAttributeNotFoundException.ATTRIBUTE_NOT_FOUND + attributeId);
            }
            attributeVector = table.getAll(new ASN1ObjectIdentifier(attributeId));
        }
        if (attributeVector.size() == 0) {
            throw new SignatureAttributeNotFoundException(SignatureAttributeNotFoundException.ATTRIBUTE_NOT_FOUND + attributeId);
        }
        if (attributeVector.size() <= index) {
            throw new SignatureAttributeNotFoundException(SignatureAttributeNotFoundException.INDEX_OUT_OF_BOUNDS);
        }
        Attribute asn1EncodedAttribute = (Attribute) attributeVector.get(index);
        if (asn1EncodedAttribute == null) {
            throw new SignatureAttributeNotFoundException(SignatureAttributeNotFoundException.ATTRIBUTE_NOT_FOUND + attributeId);
        }
        return asn1EncodedAttribute;
    }

    /**
     * Obtém a codificação do primeiro atributo com este identificador na
     * assinatura
     * @param attributeId O OID de identificação do atributo
     * @return A codificação específica do atributo
     * @throws SignatureAttributeNotFoundException
     */
    public Attribute getEncodedAttribute(String attributeId) throws SignatureAttributeNotFoundException {
        return this.getEncodedAttribute(attributeId, 0);
    }

    /**
     * Verifica a integridade da assinatura
     * @param signerCertificate O certificado do assinante
     * @param sigReport O relatório de verificação da assinatura
     * @return Indica se a assinatura é íntegra
     * @throws VerificationException Exceção em caso de erro durante a validação
     */
    public boolean verify(X509Certificate signerCertificate, SignatureReport sigReport) throws VerificationException {
        boolean integrity = false;
        try {
            SignerInformationVerifier signerInformationVerifier = this.getSignerInformationVerifier(signerCertificate);
            integrity = this.signerInformation.verify(signerInformationVerifier);
            sigReport.setAsymmetricCipher(integrity);
            sigReport.setHash(integrity);
        } catch (CMSException cmsException) {
            throw new VerificationException(VerificationException.ERROR_WHEN_VALIDATING_CMS, cmsException);
        }
        sigReport.setMessageDigest(this.signerInformation.getContentDigest());
        return integrity;
    }

    /**
     * Constrói um {@link SignerInformationVerifier} relativo ao
     * signerCertificate.
     * @param signerCertificate O certificado do assinante
     * @return O {@link SignerInformationVerifier} gerado
     * @throws VerificationException Exceção em caso de erro na construção do objeto
     */
    protected SignerInformationVerifier getSignerInformationVerifier(X509Certificate signerCertificate) throws VerificationException {
        JcaContentVerifierProviderBuilder contentVerifierProviderBuilder = new JcaContentVerifierProviderBuilder();
        ContentVerifierProvider contentVerifierProvider;
        DigestCalculatorProvider digestCalculatorProvider;
        if (signerCertificate == null) {
            return null;
        }
        try {
            contentVerifierProvider = contentVerifierProviderBuilder.build(signerCertificate);
            digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        } catch (OperatorCreationException operatorCreationException) {
            throw new VerificationException(operatorCreationException);
        }

        CMSSignatureAlgorithmNameGenerator cmsSignatureAlgorithmNameGenerator = new DefaultCMSSignatureAlgorithmNameGenerator();
        SignatureAlgorithmIdentifierFinder signatureAlgorithmIdentifierFinder = new DefaultSignatureAlgorithmIdentifierFinder();
                       
        return new SignerInformationVerifier(cmsSignatureAlgorithmNameGenerator, signatureAlgorithmIdentifierFinder, contentVerifierProvider, digestCalculatorProvider);
    }

    /**
     * Informa se a assinatura possui conteúdo destacado
     * @return Indica se a assinatura possui conteúdo destacado
     */
    public boolean isExternalSignedData() {
        return this.isDetached;
    }

    /**
     * Retorna o identificador da política de assinatura usada
     * @return O identificador da política de assinatura
     * @throws PbadException Exceção em caso de erro na obtenção da PA na assinatura
     */
    public String getSignaturePolicyIdentifier() throws PbadException {
        ASN1ObjectIdentifier sigPolicyId = null;
		try {
			Attribute attribute = this.signerInformation.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId);
			ASN1Set signaturePolicyIdentifier = attribute.getAttrValues();
			ASN1Sequence signaturePolicyId = (ASN1Sequence) signaturePolicyIdentifier.getObjectAt(0);
			sigPolicyId = (ASN1ObjectIdentifier) signaturePolicyId.getObjectAt(0);
		} catch (Exception e) {
			throw new PbadException(e.getMessage());
		}
        return sigPolicyId.getId();
    }

    /**
     * Utiliza o algoritmo indicado para realizar o resumo criptográfico da
     * assinatura
     * @param hashAlgorithmName O nome do algoritmo de resumo criptográfico
     * @return Os bytes do resumo criptográfico da assinatura
     * @throws PbadException Exceção em caso de algoritmo inválido
     */
    public byte[] getSignatureValueHash(String hashAlgorithmName) throws PbadException {
        MessageDigest messageDigest = null;
        try {
            byte[] signature = this.signerInformation.getSignature();
            messageDigest = MessageDigest.getInstance(hashAlgorithmName);
            messageDigest.update(signature);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new PbadException(PbadException.NO_SUCH_ALGORITHM, noSuchAlgorithmException);
        }
        return messageDigest.digest();
    }

    /**
     * Adiciona um atributo não-assinado
     * @param attribute O atributo a ser adicionado na assinatura
     * @throws PbadException Exceção em caso de erro na adição do atributo
     * @throws SignatureAttributeException Exceção em caso de erro no atributo a ser adicionado
     */
    public void addUnsignedAttribute(SignatureAttribute attribute) throws PbadException, SignatureAttributeException {
        List<String> attributeIdentifiers = this.getAttributeList();
        int ocurrences = 0;
        if (attribute.isUnique()) {
            for (String identifier : attributeIdentifiers) {
                if (identifier.equals(attribute.getIdentifier()))
                    ocurrences++;
            }
        }
        if (ocurrences == 0) {
            Attribute attributeEncoded = attribute.getEncoded();
            AttributeTable attributeTable = this.signerInformation.getUnsignedAttributes();
            if (attributeTable == null) {
                ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
                attributeTable = new AttributeTable(asn1EncodableVector);
            }
            ASN1EncodableVector asn1EncodableVector = attributeTable.toASN1EncodableVector();
            asn1EncodableVector.add(attributeEncoded);
            attributeTable = new AttributeTable(asn1EncodableVector);
            this.signerInformation = SignerInformation.replaceUnsignedAttributes(this.signerInformation, attributeTable);
            this.replaceSignerInformation();
        } else {
            throw new UniqueAttributeException(UniqueAttributeException.DUPLICATED_ATTRIBUTE + attribute.getIdentifier());
        }
    }

    /**
     * Adiciona uma contra-assinatura.
     * Esse método não deve ser utilizado por usuários da biblioteca.
     * Para a adição de contra assinaturas o usuário deve utiliza a classe
     * {@link CounterSignatureGenerator}
     * @param counterSignatureAttribute O atributo da contra-assinatura
     */
    public void addCounterSignature(IdCounterSignature counterSignatureAttribute) {
        IdCounterSignature counterSignature = (IdCounterSignature) counterSignatureAttribute;
        counterSignature.setParent(this);
        SignerInformation counterSigner = counterSignature.getSignerInformation();
        // pegando informacoes do contra-assinante
        Collection<SignerInformation> collectionInfo = new ArrayList<SignerInformation>();
        collectionInfo.add(counterSigner);
        SignerInformationStore counterSignerStore = new SignerInformationStore(collectionInfo);
        // colocando contra-assinatura dentro dos atributos não assinados do
        // assinante
        this.signerInformation = SignerInformation.addCounterSigners(this.signerInformation, counterSignerStore);
        this.replaceSignerInformation();
    }

    /**
     * Retorna o {@link SignerInformation}.
     * @return O conjunto de informações do assinante
     * */
    public SignerInformation getSignerInformation() {
        return this.signerInformation;
    }

    /**
     * Retorna os bytes de uma assinatura
     * @return Valor em bytes da assinatura
     */
    public byte[] getSignatureValue() {
        return this.signerInformation.getSignature();
    }

    /**
     * Retorna os atributos não-assinados
     * @return Os atributos não-assinados
     */
    public AttributeTable getUnsignedAttributes() {
        return this.signerInformation.getUnsignedAttributes();
    }

    /**
     * Retorna os atributos assinados
     * @return Os atributos assinados
     */
    public AttributeTable getSignedAttributes() {
        return this.signerInformation.getSignedAttributes();
    }

    /**
     * Retorna a contra-assinatura
     * @param signerCertificate O certificado do contra assinante que se deseja obter a contra
     *            assinatura
     * @return A contra-assinatura feita pelo assinante dado
     * @throws CounterSignatureException Exceção em caso de erro durante a busca pela contra-assinatura
     */
    public CounterSignatureInterface getCounterSignature(X509Certificate signerCertificate) throws CounterSignatureException {
        boolean isEqualsSignerId = false;
        IdCounterSignature counterSignature = null;
        SignerId signerIdentifier = this.buildSignerIdentifier(signerCertificate);
        Iterator<CounterSignatureInterface> counterSignatures = this.getCounterSignatures().iterator();
        while (counterSignatures.hasNext() && !isEqualsSignerId) {
            counterSignature = (IdCounterSignature) counterSignatures.next();
            if (counterSignature.getSignerInformation().getSID().equals(signerIdentifier)) {
                isEqualsSignerId = true;
            }
        }
        if (!isEqualsSignerId) {
            throw new CounterSignatureException(CounterSignatureException.COUNTER_SIGNER_NOT_FOUND);
        }
        return counterSignature;
    }

    /**
     * Retorna a lista de todas as contra-assinaturas
     * @return A lista de contra-assinaturas
     */
    public List<CounterSignatureInterface> getCounterSignatures() {
        List<CounterSignatureInterface> counterSignatures = new ArrayList<CounterSignatureInterface>();
        SignerInformationStore counterSignerInformationStore = this.signerInformation.getCounterSignatures();
        if (counterSignerInformationStore != null) {
            for (SignerInformation temporary : counterSignerInformationStore.getSigners()) {
                counterSignatures.add(new IdCounterSignature(temporary, this));
            }
        }
        return counterSignatures;
    }

    /**
     * Contrói um {@link SignerId} para o certificado passado como parâmetro
     * @param counterSignerCertificate Certificado o qual será criado um
     *            {@link SignerId}
     * @return O objeto {@link SignerId} criado
     */
    protected SignerId buildSignerIdentifier(X509Certificate counterSignerCertificate) {
        X500Name x500Name = new X500Name(counterSignerCertificate.getIssuerX500Principal().toString());
        BigInteger serialNumber = counterSignerCertificate.getSerialNumber();
        SignerId signerId = new SignerId(x500Name, serialNumber);
        return signerId;
    }

    /**
     * Substitui um atributo não assinado qualquer
     * @param attribute O atributo que foi atualizado
     * @param index O índice do atributo em relação aos seus similares
     * @throws PbadException Exceção em caso de erro na substituição do atributo
     * @throws SignatureAttributeException Exceção em caso de erro no atributo a ser substituído
     */
    public void replaceUnsignedAttribute(SignatureAttribute attribute, Integer index) throws PbadException, SignatureAttributeException {
        Attribute attributeEncoded = attribute.getEncoded();
        AttributeTable attributeTable = this.signerInformation.getUnsignedAttributes();
        if (attributeTable == null) {
            ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
            attributeTable = new AttributeTable(asn1EncodableVector);
        }
        ASN1EncodableVector oldAsn1EncodableVector = attributeTable.toASN1EncodableVector();
        ASN1EncodableVector newAsn1EncodableVector = new ASN1EncodableVector();
        int currentAttributeIndex = -1;
        for (int i = 0; i < oldAsn1EncodableVector.size(); i++) {
            Attribute currentAttribute = (Attribute) oldAsn1EncodableVector.get(i);
            if (currentAttribute.getAttrType().equals(attributeEncoded.getAttrType())) {
                currentAttributeIndex++;
                if (currentAttributeIndex == index) {
                    newAsn1EncodableVector.add(attributeEncoded);
                } else {
                    newAsn1EncodableVector.add(currentAttribute);
                }
            } else {
                newAsn1EncodableVector.add(currentAttribute);
            }
        }
        AttributeTable newAttributeTable = new AttributeTable(newAsn1EncodableVector);
        this.signerInformation = SignerInformation.replaceUnsignedAttributes(this.signerInformation, newAttributeTable);
        this.replaceSignerInformation();
    }

    /**
     * Substitui o primeiro contra-assinante que tiver o mesmo identificador do
     * assinante passado como parâmetro.
     * @param counterSignerToReplace O contra-assinante a ser substituído
     */
    @Override
    public void replaceChildSignature(SignerInformation counterSignerToReplace) {
        ASN1EncodableVector oldAsn1EncodableVector = this.signerInformation.getUnsignedAttributes().toASN1EncodableVector();
        ASN1EncodableVector newAsn1EncodableVector = new ASN1EncodableVector();
        for (int j = 0; j < oldAsn1EncodableVector.size(); j++) {
            Attribute attribute = (Attribute) oldAsn1EncodableVector.get(j);
            if (attribute.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_counterSignature)) {
                // a variável attributeValue pode ser tanto uma instância de
                // SignerInfo
                // como de DERSequence. Isso acontece pois quando você carrega
                // um CMSSignedData (criado
                // pela biblioteca BouncyCastle) do disco, os objetos deste CMS
                // são tratados
                // como objetos do pacote org.bouncycastle.asn1, e quando você
                // obtêm
                // um CMSSignedData sem carregá-lo do disco os objetos desde CMS
                // são do
                // pacote org.bouncycastle.asn1.cms
                Object attributeValue = attribute.getAttrValues().getObjectAt(0);
                SignerInfo signerInfo = null;
                if (attributeValue instanceof SignerInfo) {
                    signerInfo = (SignerInfo) attributeValue;
                } else {
                    ASN1Sequence derSequence = (ASN1Sequence) attribute.getAttrValues().getObjectAt(0);
                    signerInfo = SignerInfo.getInstance(derSequence);
                }
                if (signerInfo.getSID().equals(counterSignerToReplace.toASN1Structure().getSID())) {
                   ASN1ObjectIdentifier objectIdentifier = new ASN1ObjectIdentifier(PKCSObjectIdentifiers.pkcs_9_at_counterSignature.getId());
                    DERSet derSet = new DERSet(counterSignerToReplace.toASN1Structure());
                    attribute = new Attribute(objectIdentifier, derSet);
                    newAsn1EncodableVector.add(attribute);
                } else {
                    newAsn1EncodableVector.add(attribute);
                }
            } else {
                newAsn1EncodableVector.add(attribute);
            }
        }
        this.signerInformation = SignerInformation.replaceUnsignedAttributes(this.signerInformation, new AttributeTable(
                newAsn1EncodableVector));
        this.replaceSignerInformation();
    }

    /**
     * Utiliza o algoritmo indicado para realizar o resumo criptográfico das
     * seguintes informações em ordem: - Valor da assinatura - Carimbo do tempo
     * da assinatura - Referências de certificados completa - Referências de
     * dados de validação completa - Referências de certificados de atributo
     * completas* - Referências de dados de validação de certificados de
     * atributo completa*
     *
     * Os ultimos iténs indicados com * são opicionais e podem ou não estar
     * presentes. Os outros dados devem necessáriamente estar presentes para que
     * se possa obter o resumo criptográfico.
     * @param hashAlgorithmName O algoritmo a ser utilizado para o resumo
     * @return Os bytes do resumo criptográfico
     * @throws PbadException Exceção em caso de erro no cálculo
     */
    public byte[] getSigAndRefsHashValue(String hashAlgorithmName) throws PbadException {
        byte[] signature = this.getSignatureValue();
        byte[] signatureTimeStamp = this.getSignatureTimeStamp();
        byte[] completeCertificatesRefs = this.getCompleteCertificateRefs();
        byte[] completeRevocationRefs = this.getCompleteRevocationRefs();
        byte[] bytes = null;
        bytes = this.concatenateBytes(signature, signatureTimeStamp);
        bytes = this.concatenateBytes(bytes, completeCertificatesRefs);
        bytes = this.concatenateBytes(bytes, completeRevocationRefs);
        if (this.hasAttributeRefs()) {
            byte[] attributeCertificateRefs = this.getAttributeCertificateRefs();
            byte[] attributeRevocationRefs = this.getAttributeRevocationRefs();
            bytes = this.concatenateBytes(bytes, attributeCertificateRefs);
            bytes = this.concatenateBytes(bytes, attributeRevocationRefs);
        }
        MessageDigest digester = null;
        try {
            digester = MessageDigest.getInstance(hashAlgorithmName);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new PbadException(SignatureAttributeException.NO_SUCH_ALGORITHM);
        }
        return digester.digest(bytes);
    }

    /**
     * Retorna os bytes do atributo IdAaEtsAttrRevocationRefs
     * @return Os bytes do atributo IdAaEtsAttrRevocationRefs
     * @throws PbadException Exceção caso o atributo não seja encontrado
     */
    private byte[] getAttributeRevocationRefs() throws PbadException {
        return this.getUnsignedAttributeBytes(IdAaEtsAttrRevocationRefs.IDENTIFIER);
    }

    /**
     * Retorna os bytes do atributo IdAaEtsAttrCertificateRefs
     * @return Os bytes do atributo IdAaEtsAttrCertificateRefs
     * @throws PbadException Exceção caso o atributo não seja encontrado
     */
    private byte[] getAttributeCertificateRefs() throws PbadException {
        return this.getUnsignedAttributeBytes(IdAaEtsAttrCertificateRefs.IDENTIFIER);
    }

    /**
     * Retorna os bytes do atributo IdAaEtsAttrCertificateRefs
     * @return Os bytes do atributo IdAaEtsAttrCertificateRefs
     * @throws PbadException Exceção caso o atributo não seja encontrado
     */
    private boolean hasAttributeRefs() {
        Set<String> attributesSet = new HashSet<String>(this.getAttributeList());
        return attributesSet.contains(IdAaEtsAttrCertificateRefs.IDENTIFIER);
    }

    /**
     * Retorna os bytes do atributo id_aa_ets_revocationRefs
     * @return Os bytes do atributo id_aa_ets_revocationRefs
     * @throws PbadException Exceção caso o atributo não seja encontrado
     */
    private byte[] getCompleteRevocationRefs() throws PbadException {
        return this.getUnsignedAttributeBytes(PKCSObjectIdentifiers.id_aa_ets_revocationRefs.getId());
    }

    /**
     * Retorna os bytes do atributo id_aa_ets_certificateRefs
     * @return Os bytes do atributo id_aa_ets_certificateRefs
     * @throws PbadException Exceção caso o atributo não seja encontrado
     */
    private byte[] getCompleteCertificateRefs() throws PbadException {
        return this.getUnsignedAttributeBytes(PKCSObjectIdentifiers.id_aa_ets_certificateRefs.getId());
    }

    /**
     * Retorna os bytes do atributo id_aa_signatureTimeStampToken
     * @return Os bytes do atributo id_aa_signatureTimeStampToken
     * @throws PbadException Exceção caso o atributo não seja encontrado
     */
    private byte[] getSignatureTimeStamp() throws PbadException {
        return this.getUnsignedAttributeBytes(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken.getId());
    }

    /**
     * Retorna os bytes do atributo não-assinado indicado
     * @param id O identificados do atributo
     * @return Os bytes do atributo não-assinado
     * @throws PbadException Exceção caso o atributo não seja encontrado
     */
    private byte[] getUnsignedAttributeBytes(String id) throws PbadException {
        AttributeTable unsignedAttributes = this.signerInformation.getUnsignedAttributes();
        Attribute attribute = unsignedAttributes.get(new ASN1ObjectIdentifier(id));
        if (attribute == null)
            throw new PbadException("Necessário atributo que não está presente");
        
        byte[] attributeBytes = null;
        try {
        	byte[] attrType = attribute.getAttrType().toASN1Primitive().getEncoded();
        	attributeBytes = this.concatenateBytes(attrType, attribute.getAttrValues().toASN1Primitive().getEncoded());
        } catch (IOException ioException) {
			throw new PbadException(ioException.getMessage());
		}
        
		return attributeBytes;
    }

    /**
     * Concatena os bytes provinientes dos arrays <b>first</b> e <b>second</b>
     * em ordem, ou seja, é retornado um array em que o começo é formado pelos
     * bytes de first e os bytes finais são de second.
     * @param first Os bytes iniciais
     * @param second Os bytes finais
     * @return Os dois arrays de bytes concatenados
     */
    private byte[] concatenateBytes(byte[] first, byte[] second) {
        byte[] result = null;
        if (first == null) {
            result = second;
        } else if (second == null) {
            result = first;
        } else {
            result = new byte[first.length + second.length];
            System.arraycopy(first, 0, result, 0, first.length);
            System.arraycopy(second, 0, result, first.length + 0, second.length);
        }
        return result;
    }

    /**
     * Atualiza as informações do {@link SignerInformation} da assinatura
     */
    protected void replaceSignerInformation() {
        this.parent.replaceChildSignature(this.signerInformation);
    }

    /**
     * Retorna o identificador do assinante
     */
    public String toString() {
        return this.signerInformation.getSID().toString();
    }

    /**
     * Retorna o modo de assinatura
     * @return O modo da assinatura
     */
    public SignatureModeCAdES getMode() {
    	SignatureModeCAdES signatureMode = null;
        signatureMode = SignatureModeCAdES.ATTACHED;
        if (this.isDetached) {
            signatureMode = SignatureModeCAdES.DETACHED;
        }
        return signatureMode;
    }

    /**
     * Obtem a URI da LPA que contém a política de assinatura da assinatura
     * @return A URI da LPA
     */
    public String getSignaturePolicyUri() {
        String lpaUri = null;
        Attribute attribute = this.signerInformation.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId);
        ASN1Set signaturePolicyIdentifier = attribute.getAttrValues();
        ASN1Sequence signaturePolicyId = (ASN1Sequence) signaturePolicyIdentifier.getObjectAt(0);
        if(signaturePolicyId.size() < 3)  
        	return null; //Caso não exista o qualifier.
        ASN1Sequence sigPolicyQualifiersSequence = (ASN1Sequence) signaturePolicyId.getObjectAt(2);
        if (sigPolicyQualifiersSequence.getObjectAt(0) instanceof ASN1Sequence) {
            ASN1Sequence qualifierSequence = (ASN1Sequence) sigPolicyQualifiersSequence.getObjectAt(0);
            DERIA5String lpaUriIa5String = (DERIA5String) qualifierSequence.getObjectAt(1);
            lpaUri = lpaUriIa5String.getString();
        } else if (sigPolicyQualifiersSequence.getObjectAt(0) instanceof SigPolicyQualifierInfo) {
            SigPolicyQualifierInfo qualifier = (SigPolicyQualifierInfo) sigPolicyQualifiersSequence.getObjectAt(0);
            if (qualifier.getSigPolicyQualifierId().getId().compareTo(PKCSObjectIdentifiers.id_spq_ets_uri.getId()) == 0) {
                lpaUri = qualifier.getSigQualifier().toString();
            }
        }
        return lpaUri;
    }

    /**
     * Retorna o valor de hash da política
     * @return O valor de hash da política
     */
    public String getSignaturePolicyHashValue() {
        String hashValue = null;
        Attribute attribute = this.signerInformation.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId);
        ASN1Set signaturePolicyIdentifier = attribute.getAttrValues();
        ASN1Sequence signaturePolicyId = (ASN1Sequence) signaturePolicyIdentifier.getObjectAt(0);
        if (signaturePolicyId.getObjectAt(1) instanceof OtherHashAlgAndValue) {
            OtherHashAlgAndValue otherHashAlgAndValue = (OtherHashAlgAndValue) signaturePolicyId.getObjectAt(1);
            hashValue = otherHashAlgAndValue.getHashValue().toString().substring(1);
        } else if (signaturePolicyId.getObjectAt(1) instanceof ASN1Sequence) {
            ASN1Sequence sigPolicyHashSequence = (ASN1Sequence) signaturePolicyId.getObjectAt(1);
            DEROctetString hashValueOctet = (DEROctetString) sigPolicyHashSequence.getObjectAt(1);
            hashValue = new String(hashValueOctet.getOctets());
        }
        return hashValue;
    }

    /**
     * Remove um atributo não-assinado
     * @param attributeId O identificador do atributo a ser removido
     * @param index O índice do atributo que será removido
     * @throws SignatureAttributeNotFoundException Exceção caso o atributo não seja encontrado
     */
    public void removeUnsignedAttribute(String attributeId, int index) throws SignatureAttributeNotFoundException {
        Attribute attribute = this.getEncodedAttribute(attributeId, index);
        ASN1ObjectIdentifier attributeOid = new ASN1ObjectIdentifier(attributeId);
        AttributeTable attributeTable = this.signerInformation.getUnsignedAttributes();
        AttributeTable updatedAttributeTable = attributeTable.remove(attributeOid);
        ASN1EncodableVector attributesWithSameOidVector = attributeTable.getAll(attributeOid);
        int count = 0;
        for (int i = 0; i < attributesWithSameOidVector.size(); i++) {
            if (!(attributesWithSameOidVector.get(i).equals(attribute))) {
                updatedAttributeTable = updatedAttributeTable.add(attributeOid, (ASN1Encodable) attributesWithSameOidVector.get(i));
            } else {
                if (count > 0) {
                    updatedAttributeTable = updatedAttributeTable.add(attributeOid, (ASN1Encodable) attributesWithSameOidVector.get(i));
                }
                count++;
            }
        }
        if (updatedAttributeTable.size() == 0) {
            this.signerInformation = SignerInformation.replaceUnsignedAttributes(this.signerInformation, null);
        } else {
            this.signerInformation = SignerInformation.replaceUnsignedAttributes(this.signerInformation, updatedAttributeTable);
        }
        this.replaceSignerInformation();
    }

    /**
     * Utiliza o algoritmo indicado para realizar o resumo criptográfico
     * do carimbo de tempo de arquivamento
     * @param hashAlgorithmName O nome do algoritmo a ser utilizado para o resumo
     * @return Os bytes do resumo criptográfico
     * @throws PbadException Exceção em caso de erro no cálculo
     */
    public byte[] getArchiveTimeStampHashValue(String hashAlgorithmName) throws PbadException {
        return getArchiveTimeStampHashValue(hashAlgorithmName, null);
    }

    /**
     * Utiliza o algoritmo indicado para realizar o resumo criptográfico
     * do carimbo de tempo de arquivamento.
     * @param hashAlgorithmName O algoritmo a ser utilizado para o resumo
     * @param timeReference A data de referência do carimbo
     * @return Os bytes do resumo criptográfico
     * @throws PbadException Exceção em caso de erro no cálculo
     */
    // Método herdado de Signature deve ser implementado 
    public byte[] getArchiveTimeStampHashValue(String hashAlgorithmName, Time timeReference) throws PbadException {
    	return getArchiveTimeStampHashValue(hashAlgorithmName, timeReference, true);
    }

    /**
     * Utiliza o algoritmo indicado para realizar o resumo criptográfico
     * do carimbo de tempo de arquivamento.
     * @param hashAlgorithmName O algoritmo a ser utilizado para o resumo
     * @param timeReference A data de referência do carimbo
     * @param hashIncludingTag Indica a forma de cálculo da hash, de acordo
     *                         com as notas 2 e 3 da página 109 do ETSI TS 101 733 V2.2.1.
     *                         Se verdadeiro, indica que o calculo é feito sem incluir tag e length.
     * @return Os bytes do resumo criptográfico
     * @throws PbadException Exceção em caso de erro no cálculo
     */
    public byte[] getArchiveTimeStampHashValue(String hashAlgorithmName, Time timeReference, boolean hashIncludingTag) throws PbadException {
        byte[] contentBytes = getEncapContentInfoBytes();
        byte[] certificatesAndCrlsBytes = getCertificatesAndCrlsBytes();
        byte[] signerInfoEncoded = getSignerInfoBytes(timeReference, hashIncludingTag);
        
        byte[] hashResult = extractHashValueFromArchiveTimestampBytes(hashAlgorithmName, contentBytes, certificatesAndCrlsBytes,
                signerInfoEncoded);

        return hashResult;
    }

    /**
     * Utiliza o algoritmo indicado para realizar o resumo criptográfico
     * do carimbo de tempo de arquivamento.
     * @param hashAlgorithmName O algoritmo a ser utilizado para o resumo
     * @param contentBytes Os bytes do conteúdo do carimbo de tempo
     * @param certificatesAndCrlsBytes  Os bytes dos certificados e CRLs
     * @param signerInfoEncoded Bytes das informações do assinante
     * @return Os bytes do resumo criptográfico
     * @throws PbadException Exceção em caso de erro no cálculo
     */
    private byte[] extractHashValueFromArchiveTimestampBytes(String hashAlgorithmName, byte[] contentBytes,
            byte[] certificatesAndCrlsBytes, byte[] signerInfoEncoded) throws PbadException {
        byte[] archiveTimeStampEncoded = this.concatenateBytes(contentBytes, certificatesAndCrlsBytes);
        archiveTimeStampEncoded = this.concatenateBytes(archiveTimeStampEncoded, signerInfoEncoded);
        MessageDigest digester = null;
        try {
            digester = MessageDigest.getInstance(hashAlgorithmName);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new PbadException(SignatureAttributeException.NO_SUCH_ALGORITHM);
        }
        byte[] hashResult = digester.digest(archiveTimeStampEncoded);
        return hashResult;
    }

    /**
     * Retorna os bytes das informações do assinante.
     * É removido um ou mais archiveTimeStamp, pois quando uma assinatura possui mais de uma carimbos do tempo.
     * O carimbo N foi criado sem a existencina dos carimbos N+1. Logo, para calcular o HASH corretamente, devemos retirar o carimbo
     * N+1.
     * @param timeReference O horário de referência do carimbo
     * @param hashWithoutTag Indica a forma de cálculo da hash, de acordo com as notas 2 e 3 da pagina
     *                      109 do ETSI TS 101 733 V2.2.1. True indica que o calculo é feito sem incluir
     *                      tag e length.
     * @return Os bytes das informações do assinante
     * @throws SignatureAttributeException Exceção em caso de erro ao bucar as informações do assinante
     */
    private byte[] getSignerInfoBytes(Time timeReference, boolean hashWithoutTag) throws SignatureAttributeException {
       byte[] signerInfoEncoded = null;
       byte[] ret = null;
        
       try {
    	   
	        if (timeReference == null) {
	            signerInfoEncoded = this.signerInformation.toASN1Structure().getEncoded(ASN1Encoding.DER);
	        } else {
	            SignerInformation signerInformationClone = this.signerInformation;
	            signerInformationClone = this.removeArchiveTimeStamp(timeReference, signerInformationClone);
	            signerInfoEncoded = signerInformationClone.toASN1Structure().getEncoded(ASN1Encoding.DER);
	        }
	        

	        ASN1Sequence cms = (ASN1Sequence) ASN1Sequence.fromByteArray(signerInfoEncoded);
	        
	        ASN1Encodable version = cms.getObjectAt(0);
	        ASN1Encodable sid = cms.getObjectAt(1);
	        ASN1Encodable digestAlgorithm = cms.getObjectAt(2);
	        ASN1Encodable signedAttrs = cms.getObjectAt(3);
	        
	        if(signedAttrs instanceof DERTaggedObject) {
	        	DERTaggedObject signedAttr = (DERTaggedObject) signedAttrs;
	        	int tagNo = signedAttr.getTagNo();
	        	if(tagNo != 0) {
	        		signedAttrs = null; 
	        	}
	        } else {
	        	signedAttrs = null;
	        }
	        
	        int sATagNumber = signedAttrs == null ? 3 : 4;
	        int sTagNumber = signedAttrs == null ? 4 : 5;
	        int usATagNumber = signedAttrs == null ? 5 : 6;
	        
	        ASN1Encodable signatureAlgorithm = cms.getObjectAt(sATagNumber);
	        ASN1Encodable signature = cms.getObjectAt(sTagNumber);
	        ASN1Encodable unsignedAttrs = cms.getObjectAt(usATagNumber);
	                
	        if(unsignedAttrs instanceof DERTaggedObject) {
	        	DERTaggedObject unSignedAttr = (DERTaggedObject) unsignedAttrs;
	        	int tagNo = unSignedAttr.getTagNo();
	        	
	        	if(tagNo != 1) {
	        		unsignedAttrs = null; 
	        	}
	        } else {
	        	unsignedAttrs = null;
	        }

	        ret = this.concatenateBytes(ret, version.toASN1Primitive().getEncoded());
	        ret = this.concatenateBytes(ret, sid.toASN1Primitive().getEncoded());
	        ret = this.concatenateBytes(ret, digestAlgorithm.toASN1Primitive().getEncoded());
	        if(signedAttrs != null)
	        	ret = this.concatenateBytes(ret, signedAttrs.toASN1Primitive().getEncoded());
	        ret = this.concatenateBytes(ret, signatureAlgorithm.toASN1Primitive().getEncoded());
	        ret = this.concatenateBytes(ret, signature.toASN1Primitive().getEncoded());


// FIXME Ver refêrencia do doc ETSI 733. Versões mais novos pedem para verificar dessa maneira, e a partir da DERTaggedObject
// Existem duas formas de calcular o hash nesse ponto, as notas 2 e 3 da pagina 109 do ETSI TS 101 733 V2.2.1 tratam disso
// Aqui está implementado apenas uma forma
//	        if(unsignedAttrs != null)
//	        	ret = this.concatenateBytes(ret, unsignedAttrs.toASN1Primitive().getEncoded());
	        if(unsignedAttrs != null) {
	    	   
				if (hashWithoutTag) {
					DERTaggedObject unSignedAttrObj = (DERTaggedObject) unsignedAttrs;
				    ASN1Primitive unSignedAttributes = unSignedAttrObj.getObject();
				    
				    ASN1Sequence unsignedAttribute = (ASN1Sequence) unSignedAttributes;
				    
				    for(int i = 0; i <unsignedAttribute.size(); i++) {		        	
				    	ret = this.concatenateBytes(ret, unsignedAttribute.getObjectAt(i).toASN1Primitive().getEncoded());	
				    }
				    
				} else {
					ret = this.concatenateBytes(ret, unsignedAttrs.toASN1Primitive().getEncoded());
				}        
	       }
	        	
       } catch (IOException ioException) {
    	   throw new SignatureAttributeException(ioException.getMessage(), ioException);
       }
		return ret;
    }

    /**
     * Retorna os bytes dos certificados e CRLs presentes na assinatura
     * @return Os bytes dos certificados e CRLs
     * @throws PbadException Exceção em caso de erro ao bucar os certificados e CRLs
     */
    private byte[] getCertificatesAndCrlsBytes() throws PbadException {
        CMSSignedData signedData = this.parent.getSignedData();
        
        
        byte[] certsAndCrlsBytes = null;

        try {
	        ASN1Sequence cms = (ASN1Sequence) ASN1Sequence.fromByteArray(signedData.toASN1Structure().getEncoded());
	        
	        ASN1TaggedObject contentInfoTagged = (ASN1TaggedObject) cms.getObjectAt(1);
	        ASN1Sequence contentInfoSequence =(ASN1Sequence) contentInfoTagged.getObjectParser(1, true);
				        
	        ASN1Encodable certificatesOrCRLOrNothing = contentInfoSequence.getObjectAt(3);
	        if(certificatesOrCRLOrNothing instanceof DERTaggedObject) {
	        	DERTaggedObject certificate = (DERTaggedObject) certificatesOrCRLOrNothing;
	        	int tagNo = certificate.getTagNo();
	        	if(tagNo == 0 || tagNo == 1) {
						certsAndCrlsBytes = this.concatenateBytes(certsAndCrlsBytes, certificate.getEncoded());
	        	}
	        }
	        
	        ASN1Encodable CRLOrNothing = contentInfoSequence.getObjectAt(4);
	        if(CRLOrNothing instanceof DERTaggedObject) {
	        	DERTaggedObject crls = (DERTaggedObject) CRLOrNothing;
	        	if(crls.getTagNo() ==  1) {
	        		certsAndCrlsBytes = this.concatenateBytes(certsAndCrlsBytes, crls.getEncoded());
	        	}
	        }
        
        } catch (IOException e) {
        	throw new PbadException(e.getMessage(), e.getCause());
        }
        
        return certsAndCrlsBytes;
    }

    /**
     * Retorna os bytes do conteúdo da assinatura
     * @return Os bytes do conteúdo da assinatura
     * @throws PbadException Exceção em caso de erro na obtenção do conteúdo
     */
    private byte[] getEncapContentInfoBytes() throws PbadException {
        byte[] contentBytes = null;
        
        CMSSignedData signedData = this.parent.getSignedData();
        ASN1Sequence signedDataSequence = null;
        
        try {
            signedDataSequence = (ASN1Sequence) ASN1Sequence.fromByteArray(signedData.toASN1Structure().getEncoded());
        } catch (IOException ioException) {
            throw new PbadException(ioException.getMessage(), ioException.getCause());
        }
        ASN1TaggedObject contentInfoTagged = (ASN1TaggedObject) signedDataSequence.getObjectAt(1);
        ASN1Sequence contentInfoSequence;
		try {
			contentInfoSequence = (ASN1Sequence) contentInfoTagged.getObjectParser(1, true);
			
			ASN1Sequence eContentSequence = (ASN1Sequence) contentInfoSequence.getObjectAt(2);
			contentBytes = eContentSequence.getEncoded();
			
			int eContentSize = eContentSequence.size();
			if (eContentSize <= 1) {
				contentBytes = this.concatenateBytes(contentBytes, this.parent.getContentToBeSigned());
			}
			
		} catch (IOException e) {
			throw new PbadException(e.getMessage(), e);
		}

        return contentBytes;
    }

    /**
     * Remove os carimbos de tempo de arquivamento da assinatura dada
     * @param timeReference O horário de referência da assinatura
     * @param signerInformation O objeto que encapsula a assinatura
     * @return Um novo objeto que encapsula a assinatura sem os carimbos de tempo de arquivamento
     * @throws SignatureAttributeException Exceção em caso de erro na busca pelos carimbos de arquivamento
     */
    private SignerInformation removeArchiveTimeStamp(Date timeReference, SignerInformation signerInformation)
        throws SignatureAttributeException {
        ASN1ObjectIdentifier asn1ObjectIdentifier = new ASN1ObjectIdentifier(IdAaEtsArchiveTimeStampV2.IDENTIFIER);
        AttributeTable attributeTable = signerInformation.getUnsignedAttributes();
        ASN1EncodableVector attributeVector = attributeTable.getAll(asn1ObjectIdentifier);
        AttributeTable updatedAttributeTable = attributeTable.remove(asn1ObjectIdentifier);
        for (int i = 0; i < attributeVector.size(); i++) {
            Attribute asn1EncodedAttribute = (Attribute) attributeVector.get(i);
            if (asn1EncodedAttribute == null) {
                throw new SignatureAttributeNotFoundException(SignatureAttributeNotFoundException.ATTRIBUTE_NOT_FOUND
                        + IdAaEtsArchiveTimeStampV2.IDENTIFIER);
            }
            IdAaEtsArchiveTimeStampV2 idAaEtsArchiveTimeStampV2 = new IdAaEtsArchiveTimeStampV2(asn1EncodedAttribute);
            Time nextTimeReference = idAaEtsArchiveTimeStampV2.getTimeReference();
            if (timeReference.compareTo(nextTimeReference) > 0) {
                updatedAttributeTable = updatedAttributeTable.add(asn1ObjectIdentifier,
                        idAaEtsArchiveTimeStampV2.getArchiveTimeStampContentInfo());
            }
        }
        if (updatedAttributeTable.size() == 0) {
            signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, null);
        } else {
            signerInformation = SignerInformation.replaceUnsignedAttributes(signerInformation, updatedAttributeTable);
        }
        return signerInformation;
    }

    /**
     * Retorna uma representação do contêiner de assinaturas.
     * @return O objeto {@link CMSSignedData}
     */
    @Override
    public CMSSignedData getSignedData() {
        return this.parent.getSignedData();
    }

    /**
     * Retorna os bytes do conteúdo que será assinado
     * @return Os bytes do conteúdo que será assinado
     */
    @Override
    public byte[] getContentToBeSigned() {
        return this.parent.getContentToBeSigned();
    }

    /**
     * Retorna o contêiner da assinatura
     * @return O contêiner da assinatura
     */
    @Override
    public SignatureContainer getContainer() {
        return this.parent.getContainer();
    }

}
