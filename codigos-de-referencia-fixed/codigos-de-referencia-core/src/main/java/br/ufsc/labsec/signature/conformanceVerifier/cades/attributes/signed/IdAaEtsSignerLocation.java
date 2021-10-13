/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.esf.SignerLocation;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * <p>
 * O atributo signer location especifica o endereço associado a uma localização
 * geográfica do signatário. Este atributo é opcional para todas as políticas do
 * Padrão Brasileiro de Assinatura Digital.
 * </p>
 * <p>
 * Mais informações: http://www.ietf.org/rfc/rfc5126.txt
 * </p>
 * 
 * <p>
 * Oid e esquema do atributo id-aa-ets-signerLocation retirado da RFC 5126:
 * </p>
 * 
 * <pre>
 * id-aa-ets-signerLocation OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
 * smime(16) id-aa(2) 17}
 * 
 * SignerLocation ::= SEQUENCE { -- at least one of the following shall be present: countryName [0] DirectoryString
 * OPTIONAL, -- As used to name a Country in X.500 localityName [1] DirectoryString OPTIONAL, -- As used to name a
 * locality in X.500 postalAdddress [2] PostalAddress OPTIONAL }
 * 
 * PostalAddress ::= SEQUENCE SIZE(1..6) OF DirectoryString
 * </pre>
 */
public class IdAaEtsSignerLocation implements SignatureAttribute {

    public static final String IDENTIFIER = PKCSObjectIdentifiers.id_aa_ets_signerLocation.getId();
    /**
     * Nome do país
     */
    private String countryName;
    /**
     * Nome da cidade
     */
    private String localityName;
    /**
     * Lista de endereços
     */
    private List<String> postalAdress;

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
    public IdAaEtsSignerLocation(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        Attribute attributeEncoded = signatureVerifier.getSignature().getEncodedAttribute(this.getIdentifier(), index);
        decode(attributeEncoded);
    }

    /**
     * <p>
     * Cria o atributo id-aa-ets-signerLocation a partir dos parâmetros
     * necessários para a criação do atributo.
     * </p>
     * 
     * @param countryName O identificador do país, como especificado no padrão
     *            internacional ISO 3166
     * @param localityName O nome do município-UF
     * @param postalAdress Lista de endereços
     */
    public IdAaEtsSignerLocation(String countryName, String localityName, List<String> postalAdress) {
        if (countryName != null)
            this.setCountryName(countryName);
        if (localityName != null)
            this.setLocalityName(localityName);
        if (postalAdress != null)
            this.setPostalAdress(postalAdress);
    }

    /**
     * Constrói um objeto {@link IdAaEtsSignerLocation}
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException
     */
    public IdAaEtsSignerLocation(Attribute attributeEncoded) throws SignatureAttributeException {
        decode(attributeEncoded);
    }

    /**
     * Constrói um objeto {@link IdAaEtsSignerLocation}
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException
     */
    private void decode(Attribute attributeEncoded) throws SignatureAttributeException {
    	ASN1Encodable derSignerLocationEncodable = null;
        derSignerLocationEncodable = attributeEncoded.getAttrValues();
        DLSet signerLocationSet = (DLSet) derSignerLocationEncodable;
        boolean hasAtLeastOne = false;
        if (signerLocationSet.getObjectAt(0) instanceof SignerLocation) {
            SignerLocation signerLocation = (SignerLocation) signerLocationSet.getObjectAt(0);
            DERSequence postalAdressSequence = (DERSequence) signerLocation.getPostalAddress();
            DERUTF8String countryNameDerUtf8 = signerLocation.getCountryName();
            if (countryNameDerUtf8 != null) {
                this.countryName = countryNameDerUtf8.getString();
                hasAtLeastOne = true;
            }
            DERUTF8String localityNameDerUtf8 = signerLocation.getLocalityName();
            if (localityNameDerUtf8 != null) {
                this.localityName = localityNameDerUtf8.getString();
                hasAtLeastOne = true;
            }
            if (postalAdressSequence != null) {
                List<String> postalAdressList = new ArrayList<String>();
                for (int i = 0; i < postalAdressSequence.size(); i++) {
                    DERTaggedObject postalAdressTagged = (DERTaggedObject) postalAdressSequence.getObjectAt(i);
                    DERUTF8String postalAdressDerUtf8 = (DERUTF8String) postalAdressTagged.getObject();
                    postalAdressList.add(postalAdressDerUtf8.getString());
                }
                this.postalAdress = postalAdressList;
                hasAtLeastOne = true;
            }
        } else {
            DLSequence signerLocationSequence = (DLSequence) signerLocationSet.getObjectAt(0);
            SignerLocation signerLocation = SignerLocation.getInstance(signerLocationSequence);
            DERUTF8String countryNameDerUtf8 = signerLocation.getCountryName();
            if (countryNameDerUtf8 != null) {
                this.countryName = countryNameDerUtf8.getString();
                hasAtLeastOne = true;
            }
            DERUTF8String localityNameDerUtf8 = signerLocation.getLocalityName();
            if (localityNameDerUtf8 != null) {
                this.localityName = localityNameDerUtf8.getString();
                hasAtLeastOne = true;
            }
            DLSequence postalAdressSequence = (DLSequence) signerLocation.getPostalAddress();
            if (postalAdressSequence != null) {
                List<String> postalAdressList = new ArrayList<String>();
                for (int i = 0; i < postalAdressSequence.size(); i++) {
                    DERTaggedObject postalAdressTagged = (DERTaggedObject) postalAdressSequence.getObjectAt(i);
                    DERUTF8String postalAdressDerUtf8 = (DERUTF8String) postalAdressTagged.getObject();
                    postalAdressList.add(postalAdressDerUtf8.getString());
                }
                this.postalAdress = postalAdressList;
                hasAtLeastOne = true;
            }
        }
        if (!hasAtLeastOne)
            throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + IdAaEtsSignerLocation.IDENTIFIER
                    + "Deve possuir pelo menos um campo");
    }

    /**
     * Atribue a lista com o postalAdress para o atributo
     * @param postalAdress A lista de endereços
     */
    private void setPostalAdress(List<String> postalAdress) {
        this.postalAdress = postalAdress;
    }

    /**
     * Atribue a localidade no atributo.
     * @param localityName O nome do município
     */
    private void setLocalityName(String localityName) {
        this.localityName = localityName;
    }

    /**
     * Atribue o identificador do país ao atributo
     * @param countryName O identificador do país
     */
    private void setCountryName(String countryName) {
        this.countryName = countryName;
    }

    /**
     * Retorna o identificador do país
     * @return O identificador do país
     */
    public String getCountryName() {
        return this.countryName;
    }

    /**
     * Retorna a localidade
     * @return A localidade
     */
    public String getLocalityName() {
        return this.localityName;
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return IdAaEtsSignerLocation.IDENTIFIER;
    }

    /**
     * <p>
     * Este metodo método não é implementado pois este não deve ser validado,
     * ele existe apenas por caráter informativo, visto que a verificação da sua
     * estrutura é feita na hora da criação do atributo
     * </p>
     */
    @Override
    public void validate() throws SignatureAttributeException {
    }

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato ASN.1
     */
    @Override
    public Attribute getEncoded() throws SignatureAttributeException {
        boolean hasAtLeastOne = false;
        DERUTF8String countryNameDerUtf8 = null;
        if (this.countryName != null) {
            countryNameDerUtf8 = new DERUTF8String(this.countryName);
            hasAtLeastOne = true;
        }
        DERUTF8String localityNameDerUtf8 = null;
        if (this.localityName != null) {
            localityNameDerUtf8 = new DERUTF8String(this.localityName);
            hasAtLeastOne = true;
        }
        DERSequence postalAdressSequence = null;
        if (this.postalAdress != null) {
            if (this.postalAdress.size() == 0)
                throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE
                        + IdAaEtsSignerLocation.IDENTIFIER + "PostalAdress deve possuir pelo menos um campo");
            hasAtLeastOne = true;
            ASN1EncodableVector postalAdressVector = new ASN1EncodableVector();
            Iterator<String> postalAdressIterator = this.postalAdress.iterator();
            int i = 0;
            while (postalAdressIterator.hasNext()) {
                DERUTF8String postalAdressDerUtf8 = new DERUTF8String(postalAdressIterator.next());
                DERTaggedObject postalAdressTagged = new DERTaggedObject(i, postalAdressDerUtf8);
                postalAdressVector.add(postalAdressTagged);
                i++;
            }
            postalAdressSequence = new DERSequence(postalAdressVector);
        }
        if (!hasAtLeastOne)
            throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + IdAaEtsSignerLocation.IDENTIFIER
                    + "Deve possuir pelo menos um campo");
        SignerLocation signerLocation = new SignerLocation(countryNameDerUtf8, localityNameDerUtf8, postalAdressSequence);
        Attribute signerLocationAttribute = new Attribute(PKCSObjectIdentifiers.id_aa_ets_signerLocation, new DERSet(signerLocation));
        return signerLocationAttribute;
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
     * Obtém a lista de endereços
     * @return A lista com os campos do postalAddress
     */
    public List<String> getPostalAdress() {
        return this.postalAdress;
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
