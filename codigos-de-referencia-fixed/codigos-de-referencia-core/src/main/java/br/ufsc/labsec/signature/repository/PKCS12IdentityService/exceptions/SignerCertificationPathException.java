/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.repository.PKCS12IdentityService.exceptions;

public class SignerCertificationPathException extends CertificationPathException {

    public static final String PROBLEM_TO_SELECT_SIGNING_CERTIFICATE_ON_CERTSTORE = "Problema ao selecionar o certificado do signatário";
    public static final String PROBLEM_TO_OBTAIN_SIGNINGCERTIFICATE = "Problema ao obter o atributo SigningCertificate";
    public static final String PROBLEM_WHEN_BUILDING_THE_CERTPATH = "Caminho de certificação não pôde ser montado";
    /**
	 * 
	 */
    private static final long serialVersionUID = 1L;
    private int certificateIndex;

    public SignerCertificationPathException(Throwable cause) {
        super(cause);
    }

    public SignerCertificationPathException(String message, int certificateIndex) {
        super(message);
        this.certificateIndex = certificateIndex;
    }

    public SignerCertificationPathException(String message, Throwable cause) {
        super(message, cause);
    }

    public SignerCertificationPathException(String message) {
        super(message);
    }

    public int getCertificateIndex() {
        return certificateIndex;
    }
}
