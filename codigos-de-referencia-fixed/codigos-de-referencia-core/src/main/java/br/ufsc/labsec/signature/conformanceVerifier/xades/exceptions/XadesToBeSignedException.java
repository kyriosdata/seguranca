/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions;

/**
 * Esta classe representa uma exceção que ocorreu durante
 * o processo de assinatura de um arquivo
 */
public class XadesToBeSignedException extends ToBeSignedException {

    private static final long serialVersionUID = 1L;

	/**
	 * Construtor
	 * @param message A mensagem de erro
	 */
	public XadesToBeSignedException(String message) {
        super(message);
    }

	/**
	 * Construtor
	 * @param cause A exceção que ocorreu
	 */
	public XadesToBeSignedException(Throwable cause) {
        super(cause);
    }

}
