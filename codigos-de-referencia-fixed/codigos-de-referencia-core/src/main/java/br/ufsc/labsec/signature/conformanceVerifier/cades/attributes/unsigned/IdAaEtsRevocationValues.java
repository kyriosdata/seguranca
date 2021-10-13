/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.esf.OtherRevVals;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.TBSCertList;

import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.RevocationValuesException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Representa os valores de revogação (LCRs ou respostas OCSP) de uma
 * assinatura.
 * <p>
 * 
 * Oid e esquema do atributo id-aa-ets-revocationValues retirado do documento
 * ETSI TS 101 733 V1.8.1:
 * <p>
 * 
 * <pre>
 * RevocationValues ::= SEQUENCE {
 * 	crlVals
 * 	[0] SEQUENCE OF CertificateList OPTIONAL,
 * 	ocspVals
 * 	[1] SEQUENCE OF BasicOCSPResponse OPTIONAL,
 * 	otherRevVals
 * 	[2] OtherRevVals OPTIONAL}
 * 
 * OtherRevVals ::= SEQUENCE {
 * 	otherRevValType OtherRevValType,
 * 	otherRevVals
 * 	ANY DEFINED BY OtherRevValType}
 * </pre>
 */
public class IdAaEtsRevocationValues implements SignatureAttribute {

    public static final String IDENTIFIER = PKCSObjectIdentifiers.id_aa_ets_revocationValues.getId();
    /**
     * Lista de CRLs
     */
    protected List<X509CRL> crlValues;
    /**
     * Lista de respostas OCSP
     */
    protected List<BasicOCSPResponse> basicOcspResponses;
    /**
     * Outras fontes de revogação
     */
    protected OtherRevVals otherRevValues;
    /**
     * Algoritmo de cálculo de hash
     */
    protected AbstractVerifier signatureVerifier;

    /**
     * Deve-se utilizar este construtor no momento de validação do atributo. O
     * parâmetro <code> index </code> deve ser usado no caso em que há mais de
     * um atributo do mesmo tipo. Caso contrário, ele deve ser zero.
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * @throws SignatureAttributeException
     */
    public IdAaEtsRevocationValues(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        this.signatureVerifier = signatureVerifier;
        Attribute genericEncoding = signatureVerifier.getSignature().getEncodedAttribute(IdAaEtsRevocationValues.IDENTIFIER, index);
        this.decode(genericEncoding);
    }

    /**
     * Construtor
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * @param id Identificador do atributo sendo decodificado. Os atributos IdAaEtsRevocationValues
     *           e RevocationInfoArchival podem ser decodificados da mesma forma
     * @throws SignatureAttributeException
     */
    public IdAaEtsRevocationValues(AbstractVerifier signatureVerifier, Integer index, String id) throws SignatureAttributeException {
        this.signatureVerifier = signatureVerifier;
        Attribute genericEncoding = signatureVerifier.getSignature().getEncodedAttribute(id, index);
        this.decode(genericEncoding);
    }

    /**
     * Este atributo representa as fontes de revogação utilizadas para
     * validação/verificação de uma determinada assinatura.
     * @param crlValues LCRs utilizadas no momento da validação/verificação de
     *            uma assinatura, se não existir, passar null como argumento
     * @param ocspValues Respostas OCSP utilizadas no momento da
     *            validação/verificação de uma assinatura, se não existir,
     *            passar null como argumento
     * @param otherRevValues Outras fontes de revogação, diferentes de LCRS e
     *            respostas OCSP, caso não exista passar NULL como argumento
     * 
     * @throws RevocationValuesException
     */
    public IdAaEtsRevocationValues(List<X509CRL> crlValues, List<BasicOCSPResponse> ocspValues, OtherRevVals otherRevValues)
            throws RevocationValuesException {

        if (crlValues == null && ocspValues == null) {
            throw new RevocationValuesException(RevocationValuesException.MISSING_ATTRIBUTES);
        }
        if (crlValues != null && ocspValues == null) {
            if (crlValues.size() == 0) {
                throw new RevocationValuesException(RevocationValuesException.MISSING_ATTRIBUTES);
            }
        }
        if (ocspValues != null && crlValues == null) {
            if (ocspValues.size() == 0) {
                throw new RevocationValuesException(RevocationValuesException.MISSING_ATTRIBUTES);
            }
        }
        if (crlValues != null && ocspValues != null) {
            if (crlValues.size() == 0 && ocspValues.size() == 0) {
                throw new RevocationValuesException(RevocationValuesException.MISSING_ATTRIBUTES);
            }
        }
        if (crlValues != null)
            this.crlValues = crlValues;
        if (ocspValues != null)
            this.basicOcspResponses = ocspValues;
        if (otherRevValues != null)
            this.otherRevValues = otherRevValues;
    }

    /**
     * Constrói um objeto {@link IdAaEtsRevocationValues}
     * @param genericEncoding O atributo codificado
     * @throws SignatureAttributeException
     */
    public IdAaEtsRevocationValues(Attribute genericEncoding) throws SignatureAttributeException {
        this.decode(genericEncoding);
    }

    /**
     * Constrói um objeto {@link IdAaEtsRevocationValues}
     * @param genericEncoding O atributo codificado
     * @throws SignatureAttributeException
     */
    protected void decode(Attribute genericEncoding) throws SignatureAttributeException {
        Attribute revocationValuesAttribute;
        revocationValuesAttribute = genericEncoding;
        ASN1Set asn1SetRevocationValues = revocationValuesAttribute.getAttrValues();
        RevocationValues revocationValues = null;
        if (asn1SetRevocationValues.getObjectAt(0) instanceof RevocationValues)
            revocationValues = (RevocationValues) asn1SetRevocationValues.getObjectAt(0);
        else {
            ASN1Sequence revocationValuesSequence = (ASN1Sequence) asn1SetRevocationValues.getObjectAt(0);
            revocationValues = RevocationValues.getInstance(revocationValuesSequence);
        }
        try {
            this.decodeCrls(revocationValues.getCrlVals());
            this.decodeOcspResponses(revocationValues.getOcspVals());
        } catch (CertificateException certificateException) {
            throw new SignatureAttributeException("Falha ao validar o atributo IdAaEtsRevocationValues",
                    certificateException.getStackTrace());
        } catch (CRLException crlException) {
            throw new SignatureAttributeException("Falha ao validar o atributo IdAaEtsRevocationValues", crlException.getStackTrace());
        } catch (IOException ioException) {
            throw new SignatureAttributeException("Falha ao validar o atributo IdAaEtsRevocationValues", ioException.getStackTrace());
        }
    }

    /**
     * Constrói o array de {@link CertificateList} conforme o ASN1 do atributo
     * @param certificateListSequence {@link ASN1Sequence} de listas de certificados
     * @return O array de {@link CertificateList} criado
     */
    protected CertificateList[] generateCrlList(ASN1Sequence certificateListSequence) {
        CertificateList[] crlList = new CertificateList[certificateListSequence.size()];
        for (int i = 0; i < certificateListSequence.size(); i++) {
            crlList[i] = CertificateList.getInstance(certificateListSequence.getObjectAt(i));
        }
        return crlList;
    }

    /**
     * Constrói o array de {@link BasicOCSPResponse} conforme o ASN1 do atributo
     * @param basicOcspSequence {@link ASN1Sequence} de repostas OCSP
     * @return O array de {@link BasicOCSPResponse} criado
     */
    protected BasicOCSPResponse[] generateBasicOCSPResponse(ASN1Sequence basicOcspSequence) {
        BasicOCSPResponse[] basicOCSPResponses = new BasicOCSPResponse[basicOcspSequence.size()];
        for (int i = 0; i < basicOcspSequence.size(); i++) {
            basicOCSPResponses[i] = BasicOCSPResponse.getInstance(basicOcspSequence.getObjectAt(i));
        }
        return basicOCSPResponses;
    }

    /**
     * Constrói um objeto {@link RevocationValues} a partir do elemento ASN.1 na assinatura
     * @param revocationValuesSequence O conteúdo ASN.1 do atributo
     * @return O objeto {@link RevocationValues} criado
     */
    @SuppressWarnings("rawtypes")
    protected RevocationValues decodeRevocationValuesSequence(ASN1Sequence revocationValuesSequence) {
        Enumeration enumeration = revocationValuesSequence.getObjects();
        CertificateList[] crlList = null;
        /* Se o conteúdo do atributo está vazio,
         o objeto RevocationValues é inicializado com valores nulos */
        if (!enumeration.hasMoreElements()) {
            return new RevocationValues(null, null, null);
        }
        ASN1TaggedObject taggedObject = (DERTaggedObject) enumeration.nextElement();
        if (taggedObject.getTagNo() == 0) {
            ASN1Sequence certificateListSequence = (ASN1Sequence) taggedObject.getObject();
            crlList = generateCrlList(certificateListSequence);
            if (enumeration.hasMoreElements()) {
                taggedObject = (ASN1TaggedObject) enumeration.nextElement();
            }
        }
        BasicOCSPResponse[] basicOCSPResponses = null;
        if (taggedObject.getTagNo() == 1) {
            ASN1Sequence basicOcspSequence = (ASN1Sequence) taggedObject.getObject();
            basicOCSPResponses = generateBasicOCSPResponse(basicOcspSequence);
        }
        return new RevocationValues(crlList, basicOCSPResponses, null);
    }

    /**
     * Adiciona os elementos do array dado à lista de CRLs
     * @param certificateList Array composto de CRLs
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws IOException Exceção em caso de erro na codificação do certificado
     * @throws CRLException Exceção em caso de erro na codificação do certificado
     */
    protected void decodeCrls(CertificateList[] certificateList) throws CertificateException, IOException, CRLException {
        if (certificateList.length > 0) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            this.crlValues = new ArrayList<X509CRL>();
            for (CertificateList list : certificateList) {
                ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(list.getEncoded());
                X509CRL crl = (X509CRL) certificateFactory.generateCRL(byteArrayInputStream);
                this.crlValues.add(crl);
            }
        }
    }

    /**
     * Adiciona os elementos do array dado à lista de respostas OCSP
     * @param basicOcspResponses Array composto de respostas OCSP
     */
    protected void decodeOcspResponses(BasicOCSPResponse[] basicOcspResponses) {
        if (basicOcspResponses.length > 0) {
            this.basicOcspResponses = new ArrayList<BasicOCSPResponse>();
            this.basicOcspResponses.addAll(Arrays.asList(basicOcspResponses));
        }
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return IdAaEtsRevocationValues.IDENTIFIER;
    }

    /**
     * Valida o atributo de acordo com suas regras específicas
     * @throws SignatureAttributeException
     */
    @Override
    public void validate() throws SignatureAttributeException {
        if (this.crlValues == null && this.basicOcspResponses == null && this.otherRevValues == null) {
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                    "O atributo IdAaEtsRevocationValues está vazio/nulo.");
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        }
        if (this.hasOnlyOneInstance()) {
            this.validateAttribute();
        } else {
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                    "A assinatura contém mais de uma instância do atributo IdAaEtsRevocationValues, isto não é permitido pelo padrão brasileiro de assinatura digital.");
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        }
    }

    /**
     * Verifica se existe somente uma instância deste atributo na assinatura
     * @return Indica se existe somente uma instância deste atributo na assinatura
     */
    protected boolean hasOnlyOneInstance() {
        boolean result = false;
        List<String> attributeList = this.signatureVerifier.getSignature().getAttributeList();
        int count = 0;
        for (String attributeOid : attributeList) {
            if (attributeOid.equals(IdAaEtsRevocationValues.IDENTIFIER))
                count++;
        }
        if (count == 1)
            result = true;
        return result;
    }

    /**
     * Responsável pela validação do atributo IdAaEtsRevocationValues
     * @throws SignatureAttributeException
     */
    protected void validateAttribute() throws SignatureAttributeException {
        boolean result = true;
        Attribute idAaEtsRevocationRefsEncoding = this.signatureVerifier.getSignature().getEncodedAttribute(
                IdAaEtsRevocationRefs.IDENTIFIER, 0);
        IdAaEtsRevocationRefs idAaEtsRevocationRefs;
        try {
            idAaEtsRevocationRefs = new IdAaEtsRevocationRefs(idAaEtsRevocationRefsEncoding);
        } catch (EncodingException encodingException) {
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                    "Falha ao instanciar o atributo IdAaEtsRevocationRefs ao tentar validar o atributo IdAaEtsRevocationValues",
                    encodingException.getStackTrace());
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        } catch (Throwable t) {
        	SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                    "Falha ao instanciar o atributo IdAaEtsRevocationRefs ao tentar validar o atributo IdAaEtsRevocationValues",
                    t.getStackTrace());
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        }

        this.verifyRevocationStatusIsNull(idAaEtsRevocationRefs);
        if (idAaEtsRevocationRefs.getCrlIds() != null)
            result = this.validateCRLsIntegrity(idAaEtsRevocationRefs);
        if (idAaEtsRevocationRefs.getOcspIds() != null)
            result &= this.validateOCSPResponsesIntegrity(idAaEtsRevocationRefs);
        if (!result) {
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                    "Não é possível validar o atributo IdAaEtsRevocationValues"
                            + "\nExiste informações no atributo IdAaEtsRevocationRefs que não constam no atributo IdAaEtsRevocationValues");
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        }
    }

    /**
     * Verifica se existe algum status de revogação setado como NULL
     * indevidamente
     * @param idAaEtsRevocationRefs O atributo {@link IdAaEtsRevocationRefs}
     * @throws SignatureAttributeException
     */
    protected void verifyRevocationStatusIsNull(IdAaEtsRevocationRefs idAaEtsRevocationRefs) throws SignatureAttributeException {
        if ((this.crlValues == null && idAaEtsRevocationRefs.getCrlIds() != null)
                || (this.basicOcspResponses == null && idAaEtsRevocationRefs.getOcspIds() != null)) {
            throw new SignatureAttributeException("Falha ao validar o atributo IdAaEtsRevocationValues."
                    + "\nExistem informações no atributo IdAaEtsRevocationRefs que não constam no atributo IdAaEtsRevocationValues");
        }
    }

    /**
     * Verifica se as CRLs presentes neste atributo são as mesmas que constam no
     * atributo {@link IdAaEtsRevocationRefs}
     * @param idAaEtsRevocationRefs O atributo {@link IdAaEtsRevocationRefs}
     * @return Indica se as CRLs presentes neste atributo forem as mesmas
     *         referenciadas no atributo IdAaEtsRevocationRefs
     * @throws SignatureAttributeException
     * @throws EncodingException
     */
    protected boolean validateCRLsIntegrity(IdAaEtsRevocationRefs idAaEtsRevocationRefs) throws SignatureAttributeException {
        boolean result = false;
        int crlsRefsSize = idAaEtsRevocationRefs.getCrlIds().size();
        int count = 0;
        for (X509CRL crlValue : this.crlValues) {
            boolean hasThisCrl = idAaEtsRevocationRefs.match(crlValue);
            if (hasThisCrl) {
                count++;
            }
        }
        if (crlsRefsSize == count) {
            result = true;
        }
        return result;
    }

    /**
     * Verifica se as respostas OCSP presentes neste atributo são as mesmas que
     * constam no atributo IdAaEtsRevocationRefs
     * @return Indica se se as respostas OCSP presentes neste atributo forem as
     *         mesmas referenciadas no atributo {@link IdAaEtsRevocationRefs}
     * @throws SignatureAttributeException
     * @throws EncodingException
     */
    protected boolean validateOCSPResponsesIntegrity(IdAaEtsRevocationRefs idAaEtsRevocationRefs) throws SignatureAttributeException {
        boolean result = false;
        int ocspRefsSize = idAaEtsRevocationRefs.getOcspIds().size();
        int count = 0;
        for (BasicOCSPResponse basicOcspRespons : this.basicOcspResponses) {
            boolean hasThisOcspResp = idAaEtsRevocationRefs.match(basicOcspRespons);
            if (hasThisOcspResp) {
                count++;
            }
        }
        if (ocspRefsSize == count) {
            result = true;
        }
        return result;
    }

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato ASN.1
     */
    @Override
    public Attribute getEncoded() throws SignatureAttributeException {
        CertificateList[] certificateList = null;
        BasicOCSPResponse[] basicOcspResp = null;
        if (this.crlValues != null)
            certificateList = this.buildCertificateList();
        if (this.basicOcspResponses != null)
            basicOcspResp = this.buildBasicOCSPResp();
        RevocationValues revocationValues = new RevocationValues(certificateList, basicOcspResp, this.otherRevValues);
        ASN1Set derSetRevocationValues = new DERSet(revocationValues);
        Attribute revocationValuesAttribute = new Attribute(new ASN1ObjectIdentifier(IdAaEtsRevocationValues.IDENTIFIER),
                derSetRevocationValues);
        return revocationValuesAttribute;
    }

    /**
     * Constrói o atributo {@link BasicOCSPResponse}
     * @return O atributo {@link BasicOCSPResponse} gerado
     * @throws SignatureAttributeException
     */
    protected BasicOCSPResponse[] buildBasicOCSPResp() throws SignatureAttributeException {
        BasicOCSPResponse[] basicOcspResponses = new BasicOCSPResponse[this.basicOcspResponses.size()];
        for (int i = 0; i < this.basicOcspResponses.size(); i++) {
            basicOcspResponses[i] = this.basicOcspResponses.get(i);
        }
        return basicOcspResponses;
    }

    /**
     * Constrói o atributo {@link CertificateList}
     * @return O atributo {@link CertificateList} gerado
     * @throws SignatureAttributeException
     */
    protected CertificateList[] buildCertificateList() throws SignatureAttributeException {
        ASN1EncodableVector asn1EncodableVector;
        CertificateList[] certificateList = new CertificateList[this.crlValues.size()];
        for (int i = 0; i < this.crlValues.size(); i++) {
            X509CRL x509CRL = this.crlValues.get(i);
            ASN1Sequence sequence;
            try {
                sequence = ASN1Sequence.getInstance(x509CRL.getEncoded());
            } catch (CRLException e) {
                ASN1Sequence asn1SequenceTBSCertList;
                try {
                    asn1SequenceTBSCertList = (ASN1Sequence) ASN1Sequence.fromByteArray(x509CRL.getTBSCertList());
                } catch (CRLException | IOException crlException) {
                    throw new SignatureAttributeException("Falha na codificação do atributo IdAaEtsRevocationValues",
                            crlException.getStackTrace());
                }
                TBSCertList tbsCertList = new TBSCertList(asn1SequenceTBSCertList);
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(new ASN1ObjectIdentifier(x509CRL.getSigAlgOID()), null);
                DERBitString signatureValue = new DERBitString(x509CRL.getSignature());
                asn1EncodableVector = new ASN1EncodableVector();
                asn1EncodableVector.add(tbsCertList);
                asn1EncodableVector.add(algorithmIdentifier);
                asn1EncodableVector.add(signatureValue);
                sequence = new DERSequence(asn1EncodableVector);
            }
            certificateList[i] = CertificateList.getInstance(sequence);
        }
        return certificateList;
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
     * Retorna a lista de CRLs
     * @return A lista de CRLs
     */
    public List<X509CRL> getCrlValues() {
        return crlValues;
    }

    /**
     * Retorna a lista de respsotas OCSP
     * @return A lista de respsotas OCSP
     */
    public List<BasicOCSPResponse> getOcspValues() {
        return this.basicOcspResponses;
    }

    /**
     * Retorna as outras fontes de revogação
     * @return As outras fontes de revogação
     */
    public OtherRevVals getOtherRevValues() {
        return otherRevValues;
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
