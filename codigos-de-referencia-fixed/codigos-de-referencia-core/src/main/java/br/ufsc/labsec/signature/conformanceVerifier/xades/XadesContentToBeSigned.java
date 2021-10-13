/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.spec.XPathType;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import br.ufsc.labsec.signature.ContentToBeSigned;
import br.ufsc.labsec.signature.conformanceVerifier.xades.SignatureModeXAdES;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.NodeOperationException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureModeException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.ToBeSignedException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.XadesToBeSignedException;

/**
 * Esta classe representa o conteúdo a ser assinado por uma assinatura XAdES.
 */
public abstract class XadesContentToBeSigned implements ContentToBeSigned {

    /**
     * Modo da assinatura
     */
    private SignatureModeXAdES mode;
    /**
     * O documento da assinatura
     */
    protected Document document;
    /**
     * Lista de operações sobre os nodos da assinatura
     */
    private List<NodeOperation> operations;
    /**
     * Nodo que conterá a assinatura
     */
    protected Element nodeToEnvelop;

    /**
     * Constrói o conteúdo a ser assinado de acordo com seu modo de assinatura
     * 
     * @param mode O modo de assinatura
     */
    public XadesContentToBeSigned(SignatureModeXAdES mode) {
        this.mode = mode;
        this.operations = new ArrayList<NodeOperation>();
    }

    /**
     * Retorna o modo como o conteúdo será assinado
     * 
     * @return O modo da assinatura
     */
    public SignatureModeXAdES getMode() {
        return this.mode;
    }

    /**
     * Indica em qual nodo a assinatura será colocada, esse nodo por definição
     * não é assinado
     * 
     * @param element O nodo que conterá a assinatura
     * 
     * @throws NodeOperationException Exceção em caso de erro na geração da operação sobre o nodo
     */
    public void setEnvelopeNode(Element element) throws NodeOperationException {
        this.nodeToEnvelop = element;
        this.addOperation(new NodeOperation(element, XPathType.Filter.SUBTRACT));
    }

    /**
     * Retorna o nodo onde a assinatura será anexada. Só é relevante caso a
     * assinatura seja Enveloped ou seja uma contra-assinatura.
     * 
     * @return O nodo que conterá a assinatura
     * 
     * @throws SignatureModeException Exceção caso o nodo não esteja definido quando a assinatura é no modo Enveloped
     */
    public Element getEnvelopNode() throws SignatureModeException {
        if (this.nodeToEnvelop == null) {
            throw new SignatureModeException(
                    "Para assinar no modo Enveloped você precisa informar em qual nodo a assinatura deve ser inserida.");
        }
        return this.nodeToEnvelop;
    }

    /**
     * Adiciona as operações que serão realizadas
     * @param nodeOperation O nodo e a operação que será realizada sobre ele
     */
    public void addOperation(NodeOperation nodeOperation) {
        this.operations.add(nodeOperation);
    }

    /**
     * Retorna uma das operações, a qual será indicada pelo indice
     * @param index O índice da operação
     * @return A operação no índice dado
     */
    public NodeOperation getOperation(Integer index) {
        return this.operations.get(index);
    }

    /**
     * Como as vezes é necessário informar em qual nodo a assinatura deve ser
     * incluída, aqui é possível obter a representação do conteúdo como
     * {@link Document} para que se possa obter o {@link Element} que representa
     * o nodo onde se deseja anexar a assinatura.
     * 
     * @return A documento da assinatura
     */
    public Document getAsDocument() {
        return this.document;
    }

    /**
     * Retorna uma instância da classe {@link Reference} com as suas respectivas
     * transformações e assumindo os atributos passados através dos parâmetros.
     * 
     * @param id O identificador da refêrencia. É útil, por exemplo, quando se adiciona um
     *            {@link br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.DataObjectFormat} na assinatura
     * @param digestMethod Identificador do algoritimo que será usado para o
     *            respectivo conteúdo
     * @param baseUri A URI base para relativizar. É útil quando se tem mais de
     *            um arquivo detached em pastas diferentes
     * 
     * @return O objeto de referÊncia criado
     * 
     * @throws SignatureModeException Exceção em caso de modo de assinatura inválido
     */
    public Reference getReference(String id, DigestMethod digestMethod, URI baseUri) throws SignatureModeException, ToBeSignedException {
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance();
        String uri = getUri(baseUri);
        Reference reference = factory.newReference(uri, digestMethod, this.mode.getTransforms(this.operations), this.mode.getType(), id);
        return reference;
    }

    /**
     * Retorna o {@link Document} se o conteúdo necessita, caso contrario o
     * retorno será <code>null</code>.
     * 
     * @return O documento da assinatura
     */
    public Document getDocument() {
        Document result = null;
        if (this.mode.needSpecificDocument())
            result = this.document;
        return result;
    }

    /**
     * Método para estender para as classes inferiores a visibilidade do
     * atributo <code>document</code>. São as subclasses dessa que são
     * responsaveis por instânciar o {@link Document}.
     * 
     * @param document A representação DOM de uma ou mais assinaturas.
     */
    protected void setDocument(Document document) {
        this.document = document;
    }

    /**
     * Esse método é útil para quando se quer instânciar um novo
     * {@link XMLObject}.
     * @return O documento XML gerado
     * @throws XadesToBeSignedException Exceção em caso de erro na geração do documento
     */
    protected Document getNewDocument() throws XadesToBeSignedException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = null;
        try {
            builder = factory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new XadesToBeSignedException(e);
        }
        return builder.newDocument();
    }

    /**
     * Retorna a lista de operações
     * @return A lista de nodos e suas operações
     */
    protected List<NodeOperation> getOperations() {
        return this.operations;
    }

    /**
     * Este método retorna a URI absoluta de onde o arquivo de assinatura deve
     * estar para tipos de assinatura destacada. Caso o modo de assinatura não
     * seja esse o retorno será null.
     * 
     * @return {@link URI}
     */
    abstract URI getBaseUri();

    /**
     * Retorna a URI para o conteúdo que será assinado.
     * 
     * @param baseUri A URI absoluta de onde o arquivo de assinatura deve estar
     *            para tipos de assinatura destacada
     * 
     * @return A URI do conteúdo que será assinado
     */
    abstract protected String getUri(URI baseUri);

    /**
     * Alguns modos de assinar exigem que a assinatura tenha Object's para
     * representar o conteúdo.
     * @param id O identificador do objeto XML
     * @return O objeto que representa o conteúdo a ser assinado
     * 
     * @throws ToBeSignedException Exceção em caso de erro na leitura do arquivo
     */
    public abstract XMLObject getObject(String id) throws ToBeSignedException;

    /**
     * Retorna o identificador de uma referência
     * 
     * @return O identificador da referência
     */
    public String getReferenceId() {
        return null;
    }

    /**
     * Indica se o modo de assinatura precisa de um {@link Document} específico.
     * 
     * @return <code>true</code> se for necessário um {@link Document}
     *         específico.
     */
    public boolean modeNeedSpecificDocument() {
        return this.mode.needSpecificDocument();
    }
}
