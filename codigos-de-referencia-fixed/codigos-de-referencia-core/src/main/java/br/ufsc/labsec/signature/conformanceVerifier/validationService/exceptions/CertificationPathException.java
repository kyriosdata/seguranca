/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.validationService.exceptions;

import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa uma exceção causada por algum problema no
 * caminho de certificação de um certificado.
 */
public class CertificationPathException extends PbadException {

    private static final long serialVersionUID = 1L;
    public static final String UNKNOW_CERT_PATH_VALIDATION = "Método de validação do caminho de certificação desconhecido.";
    public static final String INVALID_PATH = "Caminho de certificação inválido.";
    public static final String INVALID_SIGNER_CERTIFICATE = "Certificado do signatário inválido.";
    public static final String ERROR_WHEN_SELECTING_CRL_IN_THE_CERTSTORE = "Ocorreu um erro ao selecionar as CRLs no CertStore";
    public static final String NO_SUCH_ALGORITHM = "Algoritmo desconhecido para montar o caminho de certificação";
    public static final String INVALID_ALGORITHM_PARAMS_OR_ALGORITHM = "Algoritmo inválido ou dados inválidos para usar o algoritmo passado para montar o caminho de certificação";
    public static final String PROBLEM_TO_VALIDATE_CERTPATH = "Caminho de certificação inválido";
    public static final String NO_SUCH_PROVIDER = "Não foi definido o provider do BouncyCastle";
    public static final String NULL_CERT_PATH = "O caminho de certificação é nulo.";
    public static final String INVALID_SIGNER_PATH = "Caminho de certificação do signatário inválido.";

    /**
     * Construtor
     * @param cause A exceção que ocorreu durante a verificação
     */
    public CertificationPathException(Throwable cause) {
        super(cause);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public CertificationPathException(String message) {
        super(message);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param cause  A exceção que ocorreu durante a verificação
     */
    public CertificationPathException(String message, Throwable cause) {
        super(message, cause);
    }
}
