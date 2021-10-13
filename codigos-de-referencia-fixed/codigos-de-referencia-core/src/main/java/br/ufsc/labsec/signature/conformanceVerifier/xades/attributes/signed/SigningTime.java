/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed;

import java.util.HashSet;
import java.util.Set;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.NamespacePrefixMapperImp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.SignatureVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.XadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * O atributo SigningTime representa o instante da assinatura, ou seja, o
 * momento em que o signatário realiza o processo de assinatura.
 * Esquema do atributo SigningTime retirado do ETSI TS 101 903:
 * 
 * {@code
 * <xsd:element name="SigningTime" type="xsd:dateTime"/>
 * }
 */
public class SigningTime implements SignatureAttribute {

    public static final String IDENTIFIER = "SigningTime";
	/**
	 * Objeto de verificador
	 */
    protected SignatureVerifier signatureVerifier;
	/**
	 * Elemento do nodo de  SigningTime
	 */
	protected Element signingTimeElement;
	/**
	 * A data da assinatura
	 */
    protected XMLGregorianCalendar signingTimeValue;

    /**
     * Deve-se utilizar este construtor no momento de validação do atributo. O
     * parâmetro <code> index </code> deve ser usado no caso em que há mais de
     * um atributo do mesmo tipo. Caso contrário, ele deve ser zero.
     * <p>
     * 
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * 
     * @throws SignatureAttributeException
     * @throws DatatypeConfigurationException
     * @throws DOMException
     */
    public SigningTime(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        Element attributeEncoded = signatureVerifier.getSignature().getEncodedAttribute(this.getIdentifier(), index);
        decode(attributeEncoded);
        this.signatureVerifier = (SignatureVerifier) signatureVerifier;
    }

    /**
     * Cria o atributo SigningTime
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException
     */
    public SigningTime(Element attributeEncoded) throws SignatureAttributeException {
        decode(attributeEncoded);
    }

    /**
     * Cria o atributo SigningTime a partir do parâmetro necessário para a
     * criação do atributo
     * <p>
     * 
     * @param signingTimeValue A data em que a assinatura foi gerada
     * @throws SignatureAttributeException
     */
    public SigningTime(XMLGregorianCalendar signingTimeValue) throws SignatureAttributeException {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder documentBuilder = null;
        try {
            documentBuilder = documentBuilderFactory.newDocumentBuilder();
        } catch (ParserConfigurationException parserConfigurationException) {
            throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + SigningTime.IDENTIFIER,
                    parserConfigurationException.getStackTrace());
        }
        Document document = documentBuilder.newDocument();
        this.signingTimeValue = signingTimeValue;
        this.signingTimeElement = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:SigningTime");
    }

    /**
     * Decodifica o atributo, armazenando os valores
     * @param attribute O atributo codificado
     * @throws SignatureAttributeException
     */
    private void decode(Element attribute) throws SignatureAttributeException {
        this.signingTimeElement = attribute;
        try {
            this.signingTimeValue = DatatypeFactory.newInstance().newXMLGregorianCalendar(signingTimeElement.getTextContent());
        } catch (DOMException domException) {
            throw new SignatureAttributeException(domException.getMessage(), domException.getStackTrace());
        } catch (DatatypeConfigurationException datatypeConfigurationException) {
            throw new SignatureAttributeException(datatypeConfigurationException.getMessage(),
                    datatypeConfigurationException.getStackTrace());
        }
    }

	/**
	 * Retorna o identificador do atributo
	 * @return O identificador do atributo
	 */
    @Override
    public String getIdentifier() {
        return SigningTime.IDENTIFIER;
    }

	/**
	 * Valida o atributo de acordo com suas regras específicas
	 * @throws SignatureAttributeException
	 */
    @Override
	public void validate() throws SignatureAttributeException {
		if (!this.signingTimeValue.isValid())
			throw new SignatureAttributeException(
					SignatureAttributeException.INVALID_SIGNATURE
							+ "A data é inválida.");
		XadesSignature xmlSignature = (XadesSignature) this.signatureVerifier
				.getSignature();
		Element xmlSignatureElement = xmlSignature.getSignatureElement();
		// NodeList signaturesList =
		// xmlSignatureElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS,"Signature");
		NodeList signingTimeList = xmlSignatureElement.getElementsByTagNameNS(
				NamespacePrefixMapperImp.XADES_NS, getIdentifier());
		int signatureAmountOfSigningTime = xmlSignatureElement
				.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
						getIdentifier()).getLength();
		int nodeAmountOfSigningTime = 0;
		for (int i = 0; i < signingTimeList.getLength(); i++) {
			Element signatureElement = (Element) signingTimeList.item(i);
			nodeAmountOfSigningTime = signatureElement.getElementsByTagNameNS(
					NamespacePrefixMapperImp.XADES_NS, getIdentifier())
					.getLength();
			signatureAmountOfSigningTime = -nodeAmountOfSigningTime;
		}

		if (signatureAmountOfSigningTime > 1)
			throw new SignatureAttributeException(
					SignatureAttributeException.INVALID_SIGNATURE
							+ "\n A assinatura possui mais de um atributo do tipo SigningTime.");
	}

	/**
	 * Retorna o atributo codificado
	 * @return O atributo em formato de nodo XML
	 * @throws SignatureAttributeException
	 */
    @Override
    public Element getEncoded() throws SignatureAttributeException {
        this.signingTimeElement.setTextContent(this.signingTimeValue.toString());
        return this.signingTimeElement;
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
     * Retorna a data em que a assinatura foi gerada
     * @return A data em que a assinatura foi gerada
     */
    public XMLGregorianCalendar getSigningTimeValue() {
        return this.signingTimeValue;
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
