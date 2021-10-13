/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.x509.Time;

import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * O atributo SigningTime representa o instante da assinatura, ou seja, o
 * momento em que o signatário realiza o processo de assinatura.
 * <p>
 * Este atributo é opcional para todas as políticas do Padrão Brasileiro de
 * Assinatura Digital.
 * <p>
 * Mais informações:  http://www.ietf.org/rfc/rfc3852.txt
 * <p>
 * Oid e esquema do atributo id-signingTime retirado da RFC 3852:
 * 
 * <pre>
 * id-signingTime OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 * us(840) rsadsi(113549) pkcs(1) pkcs9(9) 5 }
 * 
 * SigningTime ::= Time
 * 
 * Time ::= CHOICE {
 * utcTime UTCTime,
 * generalizedTime GeneralizedTime }
 * </pre>
 */
public class IdSigningTime implements SignatureAttribute {

    public static final String IDENTIFIER = "1.2.840.113549.1.9.5";
    /**
     * O horário da assinatura
     */
    private Time time;
    /**
     * Objeto de verificador
     */
    private AbstractVerifier signatureVerifier;

    /**
     * Deve-se utilizar este construtor no momento de validação do atributo. O
     * parâmetro <code> index </code> deve ser usaddo no caso em que há mais de
     * um atributo do mesmo tipo. Caso contrário, ele deve ser zero.
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * @throws SignatureAttributeException
     */
    public IdSigningTime(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        Attribute attributeEncoded = signatureVerifier.getSignature().getEncodedAttribute(this.getIdentifier(), index);
        decode(attributeEncoded);
        this.signatureVerifier = signatureVerifier;
    }

    /**
     * Cria o atributo IdSigningTime a partir de um {@link Time}.
     * @param time O horário da assinatura indicado pelo assinante
     */
    public IdSigningTime(Time time) {
        this.time = time;
    }

    /**
     * Constrói um objeto {@link IdSigningTime}
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException
     */
    public IdSigningTime(Attribute attributeEncoded) throws SignatureAttributeException {
        decode(attributeEncoded);
    }

    /**
     * Constrói um objeto {@link IdSigningTime}
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException
     */
    private void decode(Attribute attributeEncoded) throws SignatureAttributeException {
        ASN1Encodable dlSigningTimeEncodable = null;
        dlSigningTimeEncodable = attributeEncoded.getAttrValues();
        DLSet signingTimeSet = (DLSet) dlSigningTimeEncodable;
        if (signingTimeSet.getObjectAt(0) instanceof Time) {
            this.time = (Time) signingTimeSet.getObjectAt(0);
        } else {
            this.time = new Time((ASN1Primitive) signingTimeSet.getObjectAt(0));
        }
    }

    /**
     * Retorna o tempo contido neste atributo
     * @return O horário da assinatura
     */
    public Time getTime() {
        return this.time;
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return IdSigningTime.IDENTIFIER;
    }

    /**
     * Valida o atributo de acordo com suas regras específicas
     * @throws SignatureAttributeException
     */
    @Override
    public void validate() throws SignatureAttributeException {
        int numberOfSigningTimeAttributes = 0;
        for (String identifier : this.signatureVerifier.getSignature().getAttributeList()) {
            if (identifier.equals(this.getIdentifier())) {
                numberOfSigningTimeAttributes++;
            }
        }
        if (numberOfSigningTimeAttributes > 1)
            throw new SignatureAttributeException(SignatureAttributeException.INVALID_SIGNATURE + IdSigningTime.IDENTIFIER
                    + "A assinatura pode possuir no máximo uma instância deste atributo");
        Attribute signingTimeAttribute = this.signatureVerifier.getSignature().getEncodedAttribute(this.getIdentifier());
        ASN1Encodable dlSigningTimeEncodable = null;
        dlSigningTimeEncodable = signingTimeAttribute.getAttrValues();
        DLSet signingTimeSet = (DLSet) dlSigningTimeEncodable;
        if (signingTimeSet.size() != 1) {
            throw new SignatureAttributeException(SignatureAttributeException.INVALID_SIGNATURE + IdSigningTime.IDENTIFIER
                    + "O atributo deve conter exatamente um valor.");
        }
    }

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato ASN1
     */
    @Override
    public Attribute getEncoded() throws SignatureAttributeException {
    	ASN1ObjectIdentifier idSigningTimeIdentifier = new ASN1ObjectIdentifier(IDENTIFIER);
        Attribute signingTimeAttribute = new Attribute(idSigningTimeIdentifier, new DLSet(time));
        return signingTimeAttribute;
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
     * Verifica se o atributo deve ter apenas uma instância na assinatura
     * @return Indica se o atributo deve ter apenas uma instância na assinatura
     */
    @Override
    public boolean isUnique() {
        return true;
    }
}
