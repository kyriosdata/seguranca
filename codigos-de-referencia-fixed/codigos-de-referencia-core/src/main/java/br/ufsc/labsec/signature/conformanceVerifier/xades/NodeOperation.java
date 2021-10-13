/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades;

import javax.xml.crypto.dsig.spec.XPathType;

import org.w3c.dom.Element;

import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.NodeOperationException;

/**
 * Esta classe associa um nodo à operação que este irá sofrer ao executar a tranformação
 * XPath2 da referência do conteúdo enveloped.
 * <p>
 * 
 * Para mais detalhes de como usar as operações o seguinte link é de grande
 * ajuda: <a href="http://www.w3.org/TR/xmldsig-filter2/">XML-Signature XPath
 * Filter 2.0</a>
 * 
 */
public class NodeOperation {

    /**
     * O nodo que sofrerá a operação
     */
    Element element;
    /**
     * A operação que será realizada sobre o nodo
     */
    XPathType.Filter operation;

    /**
     * Construção de um {@link NodeOperation}.
     * 
     * @param node Nodo que está associado a operação
     * @param operation Operação XPath 2 que será executada sobre o nodo
     * 
     * @throws NodeOperationException
     */
    public NodeOperation(Element node, XPathType.Filter operation) throws NodeOperationException {
        if (node == null || operation == null) {
            throw new NodeOperationException("Ambos os parâmetros devem ser definidos");
        }
        this.element = node;
        this.operation = operation;
    }

    /**
     * Retorna o nodo sobre o qual a operação será executada
     * 
     * @return O nodo que sofrerá a operação

     */
    public Element getElement() {
        return this.element;
    }

    /**
     * Retorna a operação que será executada sobre o nodo.
     * 
     * @return A operação que será executada
     */
    public XPathType.Filter getOperation() {
        return this.operation;
    }
}
