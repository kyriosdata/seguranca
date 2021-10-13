/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions;

import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa uma exceção causada por um {@link br.ufsc.labsec.signature.Verifier}
 */
public class SignatureVerifierException extends PbadException {

    private static final long serialVersionUID = 1L;

	/**
	 * Construtor
	 * @param message A mensagem de erro
	 */
    public SignatureVerifierException(String message) {
        super(message);
    }

    public static final String SIGNATURE_NULL = "A assinatura passada não pode ser nula.";
}
