/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions;

import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa uma exceção causada por um erro
 * no processamento do contêiner de assinatura XAdES
 */
public class XadesSignatureContainerException extends PbadException {

    private static final long serialVersionUID = 1L;

	/**
	 * Construtor
	 * @param cause A exceção que ocorreu
	 */
    public XadesSignatureContainerException(Throwable cause) {
        super(cause);
    }

}
