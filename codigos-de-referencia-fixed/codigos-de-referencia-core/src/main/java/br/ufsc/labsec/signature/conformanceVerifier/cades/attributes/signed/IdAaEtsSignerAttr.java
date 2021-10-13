/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.esf.SignerAttribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.Holder;
import org.bouncycastle.asn1.x509.ObjectDigestInfo;

import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;



/**
 * <p>
 * O atributo signer attributes especifica os atributos adicionais do
 * signatário. Ele pode ser os atributos alegados do signatário ou os atributos
 * do certificado do signatário. Este atributo é opcional para todas as
 * políticas do Padrão Brasileiro de Assinatura Digital. Mais informações:
 *  http://www.ietf.org/rfc/rfc3126.txt
 * </p>
 * 
 * <p>
 * Oid e esquema do atributo id-aa-ets-signerAttr retirado da RFC 3126:
 * </p>
 * 
 * <pre>
 * id-aa-ets-signerAttr OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 18}
 * 
 * SignerAttribute ::= SEQUENCE OF CHOICE {
 * claimedAttributes [0] ClaimedAttributes,
 * certifiedAttributes [1] CertifiedAttributes
 * }
 * 
 * ClaimedAttributes ::= SEQUENCE OF Attribute
 * 
 * CertifiedAttributes ::= AttributeCertificate
 * </pre>
 */
public class IdAaEtsSignerAttr implements SignatureAttribute {

    public static final String IDENTIFIER = PKCSObjectIdentifiers.id_aa_ets_signerAttr.getId();
    /**
     * Lista de atributos de certificado
     */
    private List<Attribute> claimedAttributes;
    /**
     * Certificado de atributo
     */
    private AttributeCertificate attributeCertificate;
    /**
     * Objeto de verificador
     */
    private AbstractVerifier signatureVerifier;
//    public static final String[] claimedAttributesOidAllowed = { "2.5.18.1", "2.5.18.2", "2.5.18.3", "2.5.18.4", "2.5.18.10", "2.5.21.5",
//        "2.5.21.6", "2.5.21.4", "2.5.21.8" };
    public static final String[] attributesCertificateOidAllowed = { "1.3.6.1.5.5.7.10.1", "1.3.6.1.5.5.7.10.2", "1.3.6.1.5.5.7.10.3",
        "1.3.6.1.5.5.7.10.4", "1.3.6.1.5.5.7.10.5", "2.5.4.72" };

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
    public IdAaEtsSignerAttr(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException, IOException {
        Attribute attributeEncoded = signatureVerifier.getSignature().getEncodedAttribute(this.getIdentifier(), index);
        decode(attributeEncoded);
        this.signatureVerifier = signatureVerifier;
    }

    /**
     * Atribue a lista de atributos de certificado
     * @param claimedAttributes A lista de atributos de certificado
     */
    public IdAaEtsSignerAttr(List<Attribute> claimedAttributes) {
        this.claimedAttributes = claimedAttributes;
    }

    /**
     * Atribue um certificado de atributo ao {@link IdAaEtsSignerAttr}.
     * @param attributeCertificate O certificado de atributo
     */
    public IdAaEtsSignerAttr(AttributeCertificate attributeCertificate) {
        this.attributeCertificate = attributeCertificate;
    }

    /**
     * Constrói um objeto {@link IdAaEtsSignerAttr}
     * @param genericEncoding O atributo codificado
     * @throws SignatureAttributeException
     */
    public IdAaEtsSignerAttr(Attribute genericEncoding) throws SignatureAttributeException, IOException {
        decode(genericEncoding);
    }

    /**
     * Constrói um objeto {@link IdAaEtsSignerAttr}
     * @param genericEncoding O atributo codificado
     * @throws SignatureAttributeException
     */
    private void decode(Attribute genericEncoding) throws SignatureAttributeException {
        ASN1Encodable derSignerAttrEncodable = null;

        derSignerAttrEncodable = genericEncoding;
        ASN1Sequence signerAttrSet = (ASN1Sequence) derSignerAttrEncodable.toASN1Primitive();
        ASN1Set asn1Set = (ASN1Set) signerAttrSet.getObjectAt(1);
        if (asn1Set.getObjectAt(0) instanceof SignerAttribute) {
            SignerAttribute signerAttr = (SignerAttribute) asn1Set.getObjectAt(0);
            
            Object[] values = signerAttr.getValues();
            
            for (int i = 0; i < values.length; i++) {
            
            	if (values[i] instanceof Attribute[]) {
            		ASN1Sequence claimedAttributesSequence = ASN1Sequence.getInstance((Attribute[])values[i]);
            		if (this.claimedAttributes == null) {
            			this.claimedAttributes = new ArrayList<Attribute>();
            		}
            		Attribute attribute = (Attribute) claimedAttributesSequence.getObjectAt(i);
            		claimedAttributes.add(attribute);
            	} else {
            		AttributeCertificate attributeCertificate = (AttributeCertificate)values[i];
            		this.attributeCertificate = attributeCertificate;            	
            	}
            }
            
        
        } else {
            ASN1Sequence ASN1SequenceSignerAttribute = (ASN1Sequence) asn1Set.getObjectAt(0);
            ASN1TaggedObject taggedObject = (ASN1TaggedObject) ASN1SequenceSignerAttribute.getObjectAt(0);

            if (taggedObject.getTagNo() == 0) {
                try {
                    ASN1Sequence claimedAttributesSequence = (ASN1Sequence) taggedObject.getObjectParser(1, true);
                    List<Attribute> claimedAttributes = new ArrayList<Attribute>();

                    for (int i = 0; i < claimedAttributesSequence.size(); i++) {
                        if (claimedAttributesSequence.getObjectAt(i) instanceof ASN1Sequence) {
                            ASN1Sequence claimedAttributeSequence = (ASN1Sequence) claimedAttributesSequence.getObjectAt(i);
                            Attribute attribute = Attribute.getInstance(claimedAttributeSequence);
                            claimedAttributes.add(attribute);
                        } else {
                            Attribute attribute = (Attribute) claimedAttributesSequence.getObjectAt(i);
                            claimedAttributes.add(attribute);
                        }
                    }

                    this.claimedAttributes = claimedAttributes;
                } catch (IOException ignored) {
                    throw new SignatureAttributeException("ClaimedAttributes inválidos");
                }
            } else {
                try {
                    ASN1Sequence attributeCertificateSequence = (ASN1Sequence) taggedObject.getObjectParser(1, true);
                    this.attributeCertificate = AttributeCertificate.getInstance(attributeCertificateSequence);
                } catch (IOException ignored) {
                    throw new SignatureAttributeException("CertificateAttributes inválidos");
                }
            }
        }
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return IdAaEtsSignerAttr.IDENTIFIER;
    }

    /**
     * Valida se os atributos existentes são os permitidos e se conter um
     * Attribute Certificate, também valida a data de validação, o hash do
     * holder com o certificador titular, caso exista, e verifica se é possível
     * ler os valores das extensões.
     */
    @Override
    public void validate() throws SignatureAttributeException, EncodingException {
        if (this.claimedAttributes != null && this.attributeCertificate != null)
            throw new SignatureAttributeException(
                    "O atributo SignerAttribute pode conter apenas Claimed Attributes ou Attribute Certificate, jamais os dois juntos.");
        if (this.claimedAttributes != null) {
        	if(this.claimedAttributes.size() <= 0)
        		throw new SignatureAttributeException("O assinate deve ter pelo menos um atributo declarado ao usar Claimed Attributes.");
           // List<Attribute> claimedAttributes = this.claimedAttributes;
          //  Iterator<Attribute> iterator = claimedAttributes.iterator();
            //while (iterator.hasNext()) {
               // DERObjectIdentifier derOid = iterator.next().getAttrType();
                //String oid = derOid.getId();
//                if (!Arrays.asList(IdAaEtsSignerAttr.claimedAttributesOidAllowed).contains(oid))
//                    throw new SignatureAttributeException("O seguinte atributo não é permitido: Oid: " + oid);
//           }
        } else {
            AttributeCertificate attributeCertificate = this.attributeCertificate;
            Holder holder = attributeCertificate.getAcinfo().getHolder();
            ObjectDigestInfo objectDigest = holder.getObjectDigestInfo();
            if (objectDigest != null) {
                X509Certificate certificateHolder = (X509Certificate) this.signatureVerifier.getCertPath().getCertificates().get(0);
                byte[] signature = certificateHolder.getSignature();
                DERBitString signatureBitString = new DERBitString(signature);
                if (!objectDigest.equals(signatureBitString))
                    throw new SignatureAttributeException(
                            "As informações do Attribute Certificate não conferem com as do certificado do signátario.");
            }
            ASN1GeneralizedTime derNotBeforeTime = attributeCertificate.getAcinfo().getAttrCertValidityPeriod().getNotBeforeTime();
            Time notBeforeTime = null;
            try {
                notBeforeTime = new Time(derNotBeforeTime.getDate().getTime());
            } catch (ParseException parseException) {
                throw new SignatureAttributeException(parseException.getMessage());
            }
            ASN1GeneralizedTime derNotAfterTime = attributeCertificate.getAcinfo().getAttrCertValidityPeriod().getNotAfterTime();
            Time notAfterTime = null;
            try {
                notAfterTime = new Time(derNotAfterTime.getDate().getTime());
            } catch (ParseException parseException) {
                throw new SignatureAttributeException(parseException.getMessage());
            }
            Time currentDate = this.signatureVerifier.getTimeReference();
            if (currentDate.before(notBeforeTime) || currentDate.after(notAfterTime)) {
                throw new SignatureAttributeException("O atributo está fora da data de validação");
            }
            ASN1Sequence attributesSequence = attributeCertificate.getAcinfo().getAttributes();
            for (int i = 0; i < attributesSequence.size(); i++) {
                ASN1Sequence attributeSequence = (ASN1Sequence) attributesSequence.getObjectAt(i);
                ASN1ObjectIdentifier asn1Oid = (ASN1ObjectIdentifier) attributeSequence.getObjectAt(0);
                String oid = asn1Oid.getId();
                if (!Arrays.asList(IdAaEtsSignerAttr.attributesCertificateOidAllowed).contains(oid))
                    throw new SignatureAttributeException("O Attribute Certificate não permite o atributo com oid: " + oid);
            }
            Extensions extensios = attributeCertificate.getAcinfo().getExtensions();
            if (extensios != null) {
                try {
                    extensios.getExtensionOIDs();
                } catch (Exception exception) {
                    throw new SignatureAttributeException("Não foi possível ler todos os oids das extensões");
                }
            }
       }
    }

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato ASN.1
     */
    @Override
    public Attribute getEncoded() throws SignatureAttributeException {
        ASN1Encodable signerAttribute = null;
        if (this.claimedAttributes != null) {
            ASN1EncodableVector attributeVector = new ASN1EncodableVector();
            for (Attribute claimedAttribute : this.claimedAttributes) {
                ASN1Encodable derAttribute = (ASN1Encodable) claimedAttribute;
                attributeVector.add(derAttribute);
            }
            ASN1Sequence attributesSequence = ASN1Sequence.getInstance(attributeVector);
            signerAttribute = SignerAttribute.getInstance(attributesSequence);
        } else {
            signerAttribute = new SignerAttribute(this.attributeCertificate);
        }
        Attribute signerAttrAttribute = new Attribute(PKCSObjectIdentifiers.id_aa_ets_signerAttr, new DERSet(signerAttribute));
        return signerAttrAttribute;
    }

    /**
     * Informa se o atributo é assinado
     * @return Indica se o atributo é assinado
     */
    @Override
    public boolean isSigned() {
        return true;
    }

    /**
     * Obtém o certificado de atributo
     * @return O certificado de atributo
     */
    public AttributeCertificate getAttributeCertificate() {
        return this.attributeCertificate;
    }

    /**
     * Obtém a lista dos atributos de certificado
     * @return A lista dos atributos de certificado
     */
    public List<Attribute> getClaimedAttributes() {
        return this.claimedAttributes;
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
