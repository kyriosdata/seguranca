/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions;

import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa uma exceção causada pela falta
 * de informação sobre o assinante durante a geração de um objeto {@link br.ufsc.labsec.signature.conformanceVerifier.cades.SignerData}
 */
public class SignerException extends PbadException {

    public static final String MISSING_CERTIFICATE = "Você precisa passar um certificado para o assinante.";
    public static final String MISSING_PRIVATE_KEY = "Você precisa passar a chave privada do assinante.";
    public static final String MALFORMED_TBS_FILE = "Arquivo a ser assinado malformado";

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public SignerException(String message) {
        super(message);
    }

    private static final long serialVersionUID = 1L;

}
