/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed;

import java.util.List;

import org.w3c.dom.Element;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.Marshaller;
import br.ufsc.labsec.signature.conformanceVerifier.xades.NamespacePrefixMapperImp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.XmlProcessingException;

/**
 * O atributo SignatureProductionPlace especifica um endereço que associa o
 * assinante à um local geográfico particular.
 *
 * Esquema do atributo SignatureProductionPlace retirado do ETSI TS 101 903:
 * 
 * {@code
 * <xsd:element name="SignatureProductionPlace"
 * type="SignatureProductionPlaceType"/>
 * 
 * <xsd:complexType name="SignatureProductionPlaceType">
 * <xsd:sequence>
 * <xsd:element name="City" type="xsd:string" minOccurs="0"/>
 * <xsd:element
 * name="StateOrProvince" type="xsd:string" minOccurs="0"/> 
 * <xsd:element
 * name="PostalCode" type="xsd:string" minOccurs="0"/> 
 * <xsd:element
 * name="CountryName" type="xsd:string" minOccurs="0"/> 
 * </xsd:sequence>
 * </xsd:complexType>
 * }
 */
public class SignatureProductionPlace implements SignatureAttribute {

    public static final String IDENTIFIER = "SignatureProductionPlace";
    
    private static final String DEVE_POSSUIR_PELO_MENOS_UM_CAMPO = "Deve possuir pelo menos um campo";

    /**
     * Objeto de verificador
     */
    protected AbstractVerifier signatureVerifier;
    /**
     * O nome da cidade
     */
    protected String city;
    /**
     * O nome do estado/província
     */
    protected String stateOrProvince;
    /**
     * O código postal
     */
    protected String postalCode;
    /**
     * O nome do país
     */
    protected String countryName;

    /**
     * 
     * <p>
     * Deve-se utilizar este construtor no momento de validação do atributo. O
     * parâmetro <code> index </code> deve ser usado no caso em que há mais de
     * um atributo do mesmo tipo. Caso contrário, ele deve ser zero.
     * </p>
     * 
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * 
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos atributos da assinatura.
     */
    public SignatureProductionPlace(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        Element attributeEncoded = signatureVerifier.getSignature().getEncodedAttribute(this.getIdentifier(), index);
        decode(attributeEncoded);
        this.signatureVerifier = signatureVerifier;
    }

    /**
     * <p>
     * Cria o atribulo SignatureProductionPlace a partir dos parâmetros
     * necessários para a criação do atributo
     * </p>
     * 
     * @param city O nome da cidade
     * @param stateOrProvince O nome do estado/província
     * @param postalCode O código postal
     * @param countryName O nome do país
     * 
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos atributos da assinatura.
     * */
    public SignatureProductionPlace(String city, String stateOrProvince, String postalCode, String countryName) throws SignatureAttributeException {
        boolean hasAtLeastOne = false;
        if (city != null) {
            hasAtLeastOne = true;
            this.city = city;
        }
        if (stateOrProvince != null) {
            hasAtLeastOne = true;
            this.stateOrProvince = stateOrProvince;
        }
        if (postalCode != null) {
            hasAtLeastOne = true;
            this.postalCode = postalCode;
        }
        if (countryName != null) {
            hasAtLeastOne = true;
            this.countryName = countryName;
        }
        if (!hasAtLeastOne)
            throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE
                    + SignatureProductionPlace.IDENTIFIER + DEVE_POSSUIR_PELO_MENOS_UM_CAMPO);
    }

    /**
     * Constrói um objeto {@link SignatureProductionPlace}
     * @param attributeEncoded O atributo codificado
     * 
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos atributos da assinatura.
     */
    public SignatureProductionPlace(Element attributeEncoded) throws SignatureAttributeException {
        decode(attributeEncoded);
    }

    /**
     * Constrói um objeto {@link SignatureProductionPlace}
     * @param signatureProductionPlaceElement O atributo codificado
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos atributos da assinatura.
     */
    private void decode(Element signatureProductionPlaceElement) throws SignatureAttributeException {

        boolean hasAtLeastOne = false;

        Element cityElement = (Element) signatureProductionPlaceElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "City")
                .item(0);
        if (cityElement != null) {
            String city = cityElement.getTextContent();
            this.city = city;
            hasAtLeastOne = true;
        }
        Element stateOrProvinceElement = (Element) signatureProductionPlaceElement.getElementsByTagNameNS(
                NamespacePrefixMapperImp.XADES_NS, "StateOrProvince").item(0);
        if (stateOrProvinceElement != null) {
            String stateOrProvince = stateOrProvinceElement.getTextContent();
            this.stateOrProvince = stateOrProvince;
            hasAtLeastOne = true;
        }
        Element postalCodeElement = (Element) signatureProductionPlaceElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
                "PostalCode").item(0);
        if (postalCodeElement != null) {
            String postalCode = postalCodeElement.getTextContent();
            this.postalCode = postalCode;
            hasAtLeastOne = true;
        }
        Element countryNameElement = (Element) signatureProductionPlaceElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
                "CountryName").item(0);
        if (countryNameElement != null) {
            String countryName = countryNameElement.getTextContent();
            this.countryName = countryName;
            hasAtLeastOne = true;
        }
        
        if (!hasAtLeastOne)
            throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE
                    + SignatureProductionPlace.IDENTIFIER + DEVE_POSSUIR_PELO_MENOS_UM_CAMPO);
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return SignatureProductionPlace.IDENTIFIER;
    }

    /**
     * Verifica a validade do atributo neste caso se o atributo aparece somente
     * uma vez na assinatura, se não uma exceção é disparada.
     * </p>
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos atributos da assinatura.
     * */
    @Override
    public void validate() throws SignatureAttributeException {

        List<String> attributeList = signatureVerifier.getSignature().getAttributeList();
        int cont = 0;
        for (String attribute : attributeList) {
            if (attribute.equals(this.getIdentifier()))
                cont++;
        }
        if (cont > 1)
            throw new SignatureAttributeException("A assinatura contém mais do que um attributo " + this.getIdentifier());
    }

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato de nodo XML
     * @throws SignatureAttributeException
     */
    @Override
    public Element getEncoded() throws SignatureAttributeException {
//        throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_IS_NOT_IMPLEMENTED_YET);
        // FIXME - JAXB dependencies
		boolean hasAtLeastOne = false;
		if (this.city != null)
			hasAtLeastOne = true;
		if (this.stateOrProvince != null)
			hasAtLeastOne = true;
		if (this.postalCode != null)
			hasAtLeastOne = true;
		if (this.countryName != null)
			hasAtLeastOne = true;
		if (!hasAtLeastOne)
			throw new SignatureAttributeException(
					SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE
							+ SignatureProductionPlace.IDENTIFIER
							+ "Deve possuir pelo menos um campo");

//		SignatureProductionPlaceType signatureProductionPlace = new SignatureProductionPlaceType();
//		signatureProductionPlace.setCity(this.city);
//		signatureProductionPlace.setStateOrProvince(this.stateOrProvince);
//		signatureProductionPlace.setPostalCode(this.postalCode);
//		signatureProductionPlace.setCountryName(this.countryName);
		Element signatureProductionPlaceElement = null;
//		try {
//			signatureProductionPlaceElement = Marshaller
//					.marshallAttribute(IDENTIFIER,
//							SignatureProductionPlaceType.class,
//							signatureProductionPlace,
//							NamespacePrefixMapperImp.XADES_NS);
//		} catch (XmlProcessingException xmlProcessingException) {
//			throw new SignatureAttributeException(
//					xmlProcessingException.getMessage(),
//					xmlProcessingException.getStackTrace());
//		}
		return signatureProductionPlaceElement;
    }

    /**
     * Informa se o atributo é assinado.
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
