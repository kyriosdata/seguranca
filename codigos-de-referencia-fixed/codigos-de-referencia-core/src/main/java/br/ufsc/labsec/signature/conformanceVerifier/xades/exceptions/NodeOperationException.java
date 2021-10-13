/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions;

/**
 * Esta classe indica que houve erro ao definir alguma operação sobre algum nodo
 */
public class NodeOperationException extends SignatureModeException {

    private static final long serialVersionUID = 4043121955471185449L;

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public NodeOperationException(String message) {
        super(message);
    }
}
