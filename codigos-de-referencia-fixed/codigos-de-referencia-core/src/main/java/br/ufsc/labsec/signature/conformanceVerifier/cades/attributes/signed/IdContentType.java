package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed;

import java.util.logging.Level;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * O atributo content type indica o tipo de conteúdo assinado. Ele é um object
 * identifier, que é uma única string de inteiros assinado por uma autoridade
 * que define o tipo de conteúdo. Este atributo é obrigatório para todas as
 * políticas do Padrão Brasileiro de Assinatura Digital. Mais informações:
 * http://www.ietf.org/rfc/rfc3852.txt
 * 
 * Oid e esquema do atributo id-contentType retirado da RFC 3852:
 * 
 * id-contentType OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
 * rsadsi(113549) pkcs(1) pkcs9(9) 3 }
 * 
 * ContentType ::= OBJECT IDENTIFIER
 */
public class IdContentType implements SignatureAttribute {

    public static final String IDENTIFIER = PKCSObjectIdentifiers.pkcs_9_at_contentType.getId();
    /**
     * O tipo de conteúdo assinado
     */
    protected String contentType;
    /**
     * Objeto de verificador
     */
    private AbstractVerifier verifier;

    /**
     * Deve-se utilizar este construtor no momento de validação do atributo. O
     * parâmetro <code> index </code> deve ser usaddo no caso em que há mais de
     * um atributo do mesmo tipo. Caso contrário, ele deve ser zero.
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     */
    public IdContentType(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        Attribute attributeEncoded = signatureVerifier.getSignature().getEncodedAttribute(this.getIdentifier(), index);
        decode(attributeEncoded);
        this.verifier = signatureVerifier;
    }

    /**
     * Utilizado para criação do atributo contentType, o qual indica o tipo do
     * conteúdo que está sendo assinado. Ex: "1.2.840.113549.1.7.1".
     * @param contentType Um OID que representa o tipo de conteúdo assinado.
     */
    public IdContentType(String contentType) {
        setContentType(contentType);
    }

    /**
     * Constrói um objeto {@link IdContentType}
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException
     */
    public IdContentType(Attribute attributeEncoded) throws SignatureAttributeException {
        decode(attributeEncoded);
    }

    /**
     * Constrói um objeto {@link IdContentType}
     * @param attributeEncoded O atributo codificado
     */
    private void decode(Attribute attributeEncoded) throws SignatureAttributeException {
        ASN1ObjectIdentifier derObjectIdentifier = (ASN1ObjectIdentifier) attributeEncoded.getAttrValues().getObjectAt(0);
        this.contentType = derObjectIdentifier.getId();
    }

    /**
     * Retorna o OID que representa o tipo de conteúdo assinado
     * @return OID que representa o tipo de conteúdo assinado
     */
    public String getContentTypeOId() {
        return contentType;
    }

    /**
     * Atribue o tipo do conteúdo. Ex: "1.2.840.113549.1.7.1".
     * @param contentType O OID que representa o tipo de conteúdo assinado
     */
    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato ASN.1
     */
    @Override
    public Attribute getEncoded() {
        ASN1Encodable idContentTypeObjectIdentifier = new ASN1ObjectIdentifier(this.contentType);
        ASN1Set idContentTypeDerSet = new DERSet(idContentTypeObjectIdentifier);
        Attribute contentTypeAttribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_contentType, idContentTypeDerSet);
        return contentTypeAttribute;
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return IdContentType.IDENTIFIER;
    }

    /**
     * Valida o atributo de acordo com suas regras específicas
     * @throws SignatureAttributeException
     */
    @Override
    public void validate() throws SignatureAttributeException {
        CadesSignature signature = (CadesSignature) this.verifier.getSignature();
        Attribute contentType = signature.getSignerInformation().getSignedAttributes().get(PKCSObjectIdentifiers.pkcs_9_at_contentType);
        boolean isValid = false;
        if (contentType != null) {
        	ASN1ObjectIdentifier contentTypeValue = (ASN1ObjectIdentifier) contentType.getAttrValues().getObjectAt(0);
            if (contentTypeValue != null) {
                String contentTypeId = contentTypeValue.getId();
                if (contentTypeId != null) {
                    String onlyNumbers = contentTypeId.replace(".", "");
                    try {
                        Double.parseDouble(onlyNumbers);
                    } catch (Exception e) {
                        // ERRO - não é um oid
                    	Application.logger.log(Level.WARNING, "Não é um OID.", e); 
                    }
                    isValid = true;
                }
            }
        }

        if (!isValid) {
            throw new SignatureAttributeException("Atributo ContentType não é válido");
        }
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
        // TODO Auto-generated method stub
        return false;
    }
}
