/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.exceptions;

import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa uma exceção causada por um atributo desconhecido
 * em uma assinatura XAdES
 */
public class UnknowAttributeException extends PbadException {

    private static final long serialVersionUID = -2944622841301405423L;
    public static final String UNKNOW_ATTRIBUTE = "Atributo desconhecido: ";

	/**
	 * Construtor
	 * @param message A mensagem de erro
	 * @param attributeId O identificador do atributo
	 */
    public UnknowAttributeException(String message, String attributeId) {
        super(message + attributeId);
    }

}
