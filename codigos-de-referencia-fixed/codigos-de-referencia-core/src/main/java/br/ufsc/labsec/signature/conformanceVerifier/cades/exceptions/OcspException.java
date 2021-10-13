/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions;

import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa uma exceção que ocorre na manipulação
 * de respostas OCSP
 */
public class OcspException extends PbadException {

    private static final long serialVersionUID = 1L;
    public static final String WITHOUT_RESPONSE = "Não foram passadas as respostas OCSP.";
    public static final String WITHOUT_RESPONSE_FOR_CERTIFICATE = "Não há resposta OCSP para o certificado.";
    public static final String REVOKED_CERTIFICATE = "Certificado revogado.";
    public static final String ERROR_WHEN_PREPARING_VALIDATION_WITH_OCSP = "Erro ao preparar a validação por respostas OCSP";

    /**
     * Construtor
     * @param cause A exceção que ocorreu
     */
    public OcspException(Throwable cause) {
        super(cause);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public OcspException(String message) {
        super(message);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param cause  A exceção que ocorreu durante a verificação
     */
    public OcspException(String message, Exception cause) {
        super(message, cause);
    }
}
