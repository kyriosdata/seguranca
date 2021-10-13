/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.validationService.exceptions;

/**
 * Esta classe representa uma exceção causada por algum problema
 * no caminho de certificação do certificado do assinante.
 */
public class SignerCertificationPathException extends CertificationPathException {

    public static final String PROBLEM_TO_SELECT_SIGNING_CERTIFICATE_ON_CERTSTORE = "Problema ao selecionar o certificado do signatário";
    public static final String PROBLEM_TO_OBTAIN_SIGNINGCERTIFICATE = "Problema ao obter o atributo SigningCertificate";
    public static final String PROBLEM_WHEN_BUILDING_THE_CERTPATH = "Caminho de certificação não pôde ser montado";
    private static final long serialVersionUID = 1L;
    /**
     * Índice do certificado que causou a exceção
     */
    private int certificateIndex;

    /**
     * Construtor
     * @param cause A exceção que ocorreu durante a verificação
     */
    public SignerCertificationPathException(Throwable cause) {
        super(cause);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param certificateIndex Índice do certificado que causou a exceção
     */
    public SignerCertificationPathException(String message, int certificateIndex) {
        super(message);
        this.certificateIndex = certificateIndex;
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param cause A exceção que ocorreu durante a verificação
     */
    public SignerCertificationPathException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public SignerCertificationPathException(String message) {
        super(message);
    }

    /**
     * Retorna o índice do certificado
     * @return Índice do certificado que causou a exceção
     */
    public int getCertificateIndex() {
        return certificateIndex;
    }
}
