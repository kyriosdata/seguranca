/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.ess.ContentHints;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.AllDataObjectTimeStamp;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * O atributo content-hints fornece informações sobre o conteúdo assinado mais
 * interno de uma mensagem multi-camada, no qual um conteúdo é encapsulado em
 * outro.
 * <p>
 * Mais informações: http://www.ietf.org/rfc/rfc2634.txt
 * <p>
 * Oid e esquema do atributo id-aa-contentHint retirado da RFC 2634:
 * 
 * <pre>
 * ContentHints ::= SEQUENCE {
 * contentDescription UTF8String (SIZE (1..MAX)) OPTIONAL,
 * contentType ContentType }
 * 
 * id-aa-contentHint OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
 * rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 4}
 * </pre>
 */
public class IdAaContentHint implements SignatureAttribute {

    public static final String IDENTIFIER = PKCSObjectIdentifiers.id_aa_contentHint.getId();
	/**
	 * Descrição do conteúdo
	 */
	private String contentDescription;
	/**
	 * Identificador do tipo do conteúdo
	 */
    private String contentTypeId = PKCSObjectIdentifiers.data.getId();

    /**
     * Deve-se utilizar este construtor no momento de validação do atributo.<br>
     * O parâmetro <code> index </code> deve ser usado no caso em que há mais de
     * um atributo do mesmo tipo. Caso contrário, ele deve ser zero.
	 * @param signatureVerifier Usado para criar e verificar o atributo
	 * @param index Índice usado para selecionar o atributo
     * @throws SignatureAttributeException
     */
    public IdAaContentHint(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        CadesSignature signature = signatureVerifier.getSignature();
        Attribute attributeEncoded = signature.getEncodedAttribute(this.getIdentifier(), index);
        this.decode(attributeEncoded);
    }

    /**
     * Utilizado para criar o atributo contentHint com o contentType id-data,
     * que foi pré-definido e o contentDescription.
     * 
     * @param contentDescription O contentDescription do documento assinado
     */
    public IdAaContentHint(String contentDescription) {
        this.contentDescription = contentDescription;
    }

    /**
     * Constrói um objeto {@link IdAaContentHint}
     * @param genericEncoding O atributo codificado
     * @throws SignatureAttributeException
     */
    public IdAaContentHint(Attribute genericEncoding) throws SignatureAttributeException {
        this.decode(genericEncoding);
    }

	/**
	 * Constrói um objeto {@link IdAaContentHint}
	 * @param genericEncoding O atributo codificado
	 */
    private void decode(Attribute genericEncoding) throws SignatureAttributeException {
    	ASN1Encodable derContentHintEncodable = null;
        derContentHintEncodable = genericEncoding.getAttrValues();
        ASN1Set contentHintSet = (ASN1Set) derContentHintEncodable;
        if (contentHintSet.getObjectAt(0) instanceof ContentHints) {
            ContentHints contentHints = (ContentHints) contentHintSet.getObjectAt(0);
            ASN1ObjectIdentifier derUtf8ContentType = contentHints.getContentType();
            this.contentTypeId = derUtf8ContentType.getId();
            DERUTF8String derUtf8ContentDescription = contentHints.getContentDescription();
            this.contentDescription = derUtf8ContentDescription.getString();
        } else {
            ASN1Sequence contentHintSequence = (ASN1Sequence) contentHintSet.getObjectAt(0);
            DERUTF8String derUtf8ContentDescription = (DERUTF8String) contentHintSequence.getObjectAt(0);
            this.contentDescription = derUtf8ContentDescription.getString();
            ASN1ObjectIdentifier derObjectIdentifier = (ASN1ObjectIdentifier) contentHintSequence.getObjectAt(1);
            this.contentTypeId = derObjectIdentifier.getId();
        }
    }

	/**
	 * Retorna o atributo codificado
	 * @return O atributo em formato ASN1
	 * @throws SignatureAttributeException
	 */
    @Override
    public Attribute getEncoded() throws SignatureAttributeException {
    	ASN1ObjectIdentifier derObjectIdentifier = new ASN1ObjectIdentifier(this.contentTypeId);
        ContentHints contentHints;
        DERUTF8String derUtf8ContentDescription = new DERUTF8String(this.contentDescription);
        contentHints = new ContentHints(derObjectIdentifier, derUtf8ContentDescription);
        Attribute contentHintAttribute = new Attribute(PKCSObjectIdentifiers.id_aa_contentHint, new DERSet(contentHints));
        return contentHintAttribute;
    }

	/**
	 * Retorna o identificador do atributo
	 * @return O identificador do atributo
	 */
    @Override
    public String getIdentifier() {
        return IdAaContentHint.IDENTIFIER;
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
	 * Valida o atributo de acordo com suas regras específicas
	 * @throws SignatureAttributeException
	 */
    @Override
    public void validate() throws SignatureAttributeException {
        if (!this.contentTypeId.equals(PKCSObjectIdentifiers.data.getId()))
            throw new SignatureAttributeException(SignatureAttributeException.INVALID_SIGNATURE + IdAaContentHint.IDENTIFIER
                    + "O valor do campo ContentType deve ser \"" + PKCSObjectIdentifiers.data.getId() + "\"");
        int index = this.contentDescription.indexOf("Content-Type:");
        if (index == -1)
            throw new SignatureAttributeException(SignatureAttributeException.INVALID_SIGNATURE + IdAaContentHint.IDENTIFIER
                    + "Se o atributo possui o campo Content-Description, obrigatoriamente deve ter um Content-Type.");
    }

    /**
     * Retorna o ContentTypeId
     * @return O ContentTypeId
     */
    public String getContentTypeId() {
        return this.contentTypeId;
    }

    /**
     * Retorna o ContentDescription
     * @return O ContentDescription
     */
    public String getContentDescription() {
        return this.contentDescription;
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
