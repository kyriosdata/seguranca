/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.exceptions;

public class OcspException extends PbadException {

    /**
	 * 
	 */
    private static final long serialVersionUID = 1L;
    public static final String WITHOUT_RESPONSE = "Não foram passadas as respostas OCSP.";
    public static final String WITHOUT_RESPONSE_FOR_CERTIFICATE = "Não há resposta OCSP para o certificado.";
    public static final String REVOKED_CERTIFICATE = "Certificado revogado.";
    public static final String ERROR_WHEN_PREPARING_VALIDATION_WITH_OCSP = "Erro ao preparar a validação por respostas OCSP";

    public OcspException(Throwable cause) {
        super(cause);
    }

    public OcspException(String message) {
        super(message);
    }

    public OcspException(String message, Exception cause) {
        super(message, cause);
    }
}
