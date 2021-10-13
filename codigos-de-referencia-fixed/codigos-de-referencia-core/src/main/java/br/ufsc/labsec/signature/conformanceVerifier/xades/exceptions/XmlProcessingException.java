/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions;

import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa uma exceção gerada por um erro no
 * processamento de um arquivo XML.
 */
public class XmlProcessingException extends PbadException {

    private static final long serialVersionUID = -6324340022329254463L;

	/**
	 * Construtor
	 * @param cause A exceção que ocorreu
	 */
	public XmlProcessingException(Throwable cause) {
        super(cause);
    }

}
