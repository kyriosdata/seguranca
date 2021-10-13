package br.ufsc.labsec.signature.conformanceVerifier.xades;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.XmlProcessingException;

/**
 * Esta classe faz o marshall de elementos XML.
 * 
 * Para gerar os atributos xml fora da estrutura em que eles deviam estar
 * é necessário simular a ObjectFactory gerada pelo XJC. Cria-se um QName
 * que leva no construtor dois atributos sendo o primeiro o Namespace ao 
 * qual o atributo pertence, na maioria das vezes o namespace será o correspondente
 * ao valor NamespacePrefixMapperImp.XADES_NS, e o segundo o nome da tag.
 * Em seguida cria-se um JAXBElement<TipoUsado> que será usado no marshall,
 * seu construtor pede os seguintes atributos: 
 * O primeiro é o QName criado anteriormente
 * O segundo é o objeto que representa a classe do seu atributo, ela pode ser obtida
 * usando Atributo.class.
 * O terceiro não é necessário e deve ser null.
 * O quarto enfim é a instância da classe JAXB que representa o seu atributo.
 */
public class Marshaller
{
	/**
	 * Usado para realizar o marshall em elementos não-assinados
	 * @param unsignedElement O elemento para dar o marshall.
	 * @return	{@link Element} onde foi guardado o marshall do <code>unsignedElement</code>.
	 */
	public static Element marshallUnsignedProperties(Element unsignedElement) throws XmlProcessingException {
		
		Document document = unsignedElement.getOwnerDocument();
        Element unsignedProperties = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:UnsignedProperties");
        Element unsignedSignatureProperties = document.createElementNS(NamespacePrefixMapperImp.XADES_NS,
                "XAdES:UnsignedSignatureProperties");
        unsignedElement.appendChild(unsignedProperties);
        unsignedProperties.appendChild(unsignedSignatureProperties);
        return unsignedElement;
	}

	/**
	 * Cria um novo objeto {@link Document}
	 * @return O objeto {@link Document} gerado
	 * @throws XmlProcessingException exceção caso o documento não possa ser gerado
	 */
	private static Document getNewDocument() throws XmlProcessingException
	{
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder documentBuilder;
		Document document;
		try{
			documentBuilder = factory.newDocumentBuilder();
			document = documentBuilder.newDocument();
		}catch(ParserConfigurationException jaxbException){
			throw new XmlProcessingException(jaxbException);
		}
		
		return document;
	}
}
