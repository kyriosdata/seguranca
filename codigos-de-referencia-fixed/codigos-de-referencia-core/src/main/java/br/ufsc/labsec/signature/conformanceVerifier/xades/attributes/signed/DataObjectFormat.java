/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.NamespacePrefixMapperImp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.SignatureVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.XadesContentToBeSigned;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * O atributo DataObjectFormat fornece informações que descreve o formato do dos
 * objetods de dados assinados.
 * 
 * Esquema do atributo DataObjectFormat retirado do ETSI TS 101 903:
 * 
 * {@code
 * <xsd:element name="DataObjectFormat" type="DataObjectFormatType"/>
 * 
 * <xsd:complexType name="DataObjectFormatType">
 * <xsd:sequence>
 * <xsd:element name="Description" type="xsd:string" minOccurs="0"/>
 * <xsd:element name="ObjectIdentifier" type="ObjectIdentifierType"
 * minOccurs="0"/>
 * <xsd:element name="MimeType" type="xsd:string" minOccurs="0"/>
 * <xsd:element name="Encoding" type="xsd:anyURI" minOccurs="0"/>
 * </xsd:sequence>
 * <xsd:attribute name="ObjectReference" type="xsd:anyURI"
 * use="required"/>
 * </xsd:complexType>
 * }
 */
public class DataObjectFormat implements SignatureAttribute {

    public static final String IDENTIFIER = "DataObjectFormat";

    private static final String OBJECTREFERENCENULL = "O atributo ObjectReference do DataObjectFormat está nulo.";
    
    protected String objectReference;
    protected String description;
    protected String objectIdentifier;
    protected String mimeType;
    protected String encoding;
    protected SignatureVerifier verifier;
    private XadesContentToBeSigned content;
    
    /**
     * Deve-se utilizar este construtor no momento de validação do atributo. O
     * parâmetro <code> index </code> deve ser usado no caso em que há mais de
     * um atributo do mesmo tipo. Caso contrário, ele deve ser zero.
     * 
     * @param verifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * 
     * @throws SignatureAttributeException - Caso ocorra algum erro relativo aos atributos da assinatura.
     */
    public DataObjectFormat(AbstractVerifier verifier, Integer index) throws SignatureAttributeException {
        Element attributeEncoded = verifier.getSignature().getEncodedAttribute(this.getIdentifier(), index);
        decode(attributeEncoded);
        this.verifier = (SignatureVerifier) verifier;
    }

    /**
     * O parâmetro <b>objectReference</b> é obrigatório e deve referenciar a
     * refêrencia ao arquivo que este dataObject descreve. Os parâmetros
     * <b>description</b>, <b>objectIdentifier</b> e <b>mimeType</b> são
     * opicionais, mas ao menos <b>um</b> desses deve aparecer.
     * 
     * @param objectReference A referência do objeto
     * @param description Breve descrição do formato dos dados
     * @param objectIdentifier O identificador único que representa o formato
     *            dos dados
     * @param mimeType Descrição dos dados pelo tipo myme
     * @param encoding Codificação dos dados
     * 
     * * @throws SignatureAttributeException - Caso ocorra algum erro relativo aos atributos da assinatura.
     */
    public DataObjectFormat(String objectReference, String description, String objectIdentifier, String mimeType, String encoding) throws SignatureAttributeException {
        if (objectReference == null)
            throw new SignatureAttributeException(OBJECTREFERENCENULL);
        if (description == null && objectIdentifier == null && mimeType == null)
            throw new SignatureAttributeException(
                    "O DataObjectFormat está incompleto, ele deve conter pelo menos um dos seguintes atributos: Description, ObjectIdentifier ou MimeType");
        this.objectReference = objectReference;
        this.description = description;
        this.objectIdentifier = objectIdentifier;
        this.mimeType = mimeType;
        this.encoding = encoding;
    }

    /**
     * Constrói um objeto {@link DataObjectFormat} a partir de um
     * {@link Element}
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos atributos da assinatura.
     */
    public DataObjectFormat(Element attributeEncoded) throws SignatureAttributeException {
        decode(attributeEncoded);
    }

    /**
     * Constrói um objeto {@link DataObjectFormat}
     * @param dataObjectFormatElement O elemento a ser decodificado.
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos atributos da assinatura.
     */
    private void decode(Element dataObjectFormatElement) throws SignatureAttributeException {
        boolean minimunRequirementsFound = false;
        
        NodeList descriptionNodeList = dataObjectFormatElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "Description");
        minimunRequirementsFound = checkDescriptionNodeList(minimunRequirementsFound, descriptionNodeList);
        
        NodeList objectIdentifierNodeList = dataObjectFormatElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
                "ObjectIdentifier");
        minimunRequirementsFound = checkObjectIdentifierNodeList(minimunRequirementsFound, objectIdentifierNodeList);
        
        NodeList mimeTypeNodeList = dataObjectFormatElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "MimeType");
        minimunRequirementsFound = checkMimeTypeNodeList(minimunRequirementsFound, mimeTypeNodeList);
        
        NodeList endcodingNodeList = dataObjectFormatElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "Encoding");
        checkEndcodingNodeList(endcodingNodeList);
        
        String objectReference = dataObjectFormatElement.getAttribute("Reference");
        if (objectReference != null) {
            this.objectReference = objectReference;
        } else {
            throw new SignatureAttributeException(OBJECTREFERENCENULL);
        }
        
        if (!minimunRequirementsFound) {
            throw new SignatureAttributeException("O DataObjectFormat está incompleto, ele deve conter pelo menos um "
                    + "dos seguintes atributos: Description, ObjectIdentifier ou MimeType");
        }

    }

    /**
     * Extrai o método de codificação dos dados na lista de nodos
     * @param endcodingNodeList A lista de nodos de atributos enconding
     */
    private void checkEndcodingNodeList(NodeList endcodingNodeList) {
        if (endcodingNodeList != null && endcodingNodeList.getLength() > 0) {
            this.encoding = endcodingNodeList.item(0).getTextContent();
        }
    }

    /**
     * Extrai o tipo dos dados da lista de nodos
     * @param minimunRequirementsFound Requerimentos minimos encontrados.
     * @param mimeTypeNodeList Lista dos mimeType.
     * @return Indica se o mime type foi encontrado na lista
     */
    private boolean checkMimeTypeNodeList(boolean minimunRequirementsFound, NodeList mimeTypeNodeList) {
        if (mimeTypeNodeList != null && mimeTypeNodeList.getLength() > 0) {
            this.mimeType = mimeTypeNodeList.item(0).getTextContent();
            minimunRequirementsFound = true;
        }
        return minimunRequirementsFound;
    }

    /**
     * Extrai o identificador da lista de nodos
     * @param minimunRequirementsFound Requerimentos minimos encontrados.
     * @param objectIdentifierNodeList Lista dos ObjectIdentifier.
     * @return Indica se o identificadorr foi encontrado na lista
     */
    private boolean checkObjectIdentifierNodeList(boolean minimunRequirementsFound, NodeList objectIdentifierNodeList) {
        if (objectIdentifierNodeList != null && objectIdentifierNodeList.getLength() > 0) {
            this.objectIdentifier = objectIdentifierNodeList.item(0).getTextContent();
            minimunRequirementsFound = true;
        }
        return minimunRequirementsFound;
    }

    /**
     * Extrai a descrição dos dados da lista de nodos
     * @param minimunRequirementsFound Requerimentos minimos encontrados.
     * @param descriptionNodeList Lista de descrições.
     * @return Indica se a descrição foi encontrado na lista
     */
    private boolean checkDescriptionNodeList(boolean minimunRequirementsFound, NodeList descriptionNodeList) {
        if (descriptionNodeList != null && descriptionNodeList.getLength() > 0) {
            this.description = descriptionNodeList.item(0).getTextContent();
            minimunRequirementsFound = true;
        }
        return minimunRequirementsFound;
    }

    /**
     * Retorna o DataObjectFormat na forma de Objeto definido pela API JAXB
     * @return O elemento XML do atributo
     * @throws SignatureAttributeException Caso ocorra algum erro relativo aos atributos da assinatura.
     */
    public Element getEncoded() throws SignatureAttributeException {

        Document document = null;
        try {
            document = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
        } catch (ParserConfigurationException e) {
            throw new SignatureAttributeException("Problema em gerar o documento");
        }

        Element dataObjectFormat = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:DataObjectFormat");

        if (this.description !=null){
            Element description = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:Description");
            description.setTextContent(this.description);
            dataObjectFormat.appendChild(description);
        }

        if (this.objectIdentifier != null){
            Element objectIdentifier = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:ObjectIdentifier");
            objectIdentifier.setTextContent(this.objectIdentifier);
            dataObjectFormat.appendChild(objectIdentifier);
        }

        if (this.mimeType != null){
            Element mimeType = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:MimeType");
            mimeType.setTextContent(this.mimeType);
            dataObjectFormat.appendChild(mimeType);
        }

        if (this.encoding != null){
            Element encoding = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:Enconding");
            encoding.setTextContent(this.encoding);
            dataObjectFormat.appendChild(encoding);
        }

        dataObjectFormat.setAttribute("ObjectReference", "#" + this.objectReference);

        return dataObjectFormat;
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return DataObjectFormat.IDENTIFIER;
    }

    /**
     * Retorna sempre true. Esse elemento não tem regras de validação
     */
    @Override
    public void validate() {
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
     * Obtém o atributo <b>objectReference</b> que é obrigatório e deve
     * referenciar a refêrencia ao arquivo que este dataObject descreve.
     * 
     * @return O atributo objectReference.
     */
    public String getObjectReference() {
        return this.objectReference;
    }

    /**
     * Obtém o atributo <b>description</b>.
     * 
     * @return O atributo description
     */
    public String getDescription() {
        return this.description;
    }

    /**
     * Obtém o atributo <b>mimeType</b>.
     * 
     * @return O atributo mimeType.
     */
    public String getMimeType() {
        return this.mimeType;
    }

    /**
     * Define com qual conteúdo o dataObjectFormat está relacionado
     * 
     * @param content O conteúdo.
     */
    public void setContent(XadesContentToBeSigned content) {
        this.content = content;
    }

    /**
     * Informa com qual conteúdo o dataObjectFormat está relacionado
     * 
     * @return O conteúdo.
     */
    public XadesContentToBeSigned getContent() {
        return this.content;
    }

    /**
     * Verifica se o atributo deve ter apenas uma instância na assinatura
     * @return Indica se o atributo deve ter apenas uma instância na assinatura
     */
    @Override
    public boolean isUnique() {
        return false;
    }
}
