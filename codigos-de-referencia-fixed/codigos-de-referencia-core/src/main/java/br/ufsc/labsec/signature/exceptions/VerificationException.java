/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.exceptions;


public class VerificationException extends PbadException {

    public static final String SIGNER_CERTIFICATE_NOT_YET_VALID = "O certificado do signatário ainda não é válido";
    public static final String SIGNER_CERTIFICATE_EXPIRED = "O certificado do signatário já expirou";
    public static final String ERROR_WHEN_VALIDATING_CMS = "Problema ao verificar o CMS";
    public static final String BOUNCYCASTLE_PROVIDER_NOT_ADDED = "O provider do BouncyCastle não foi incluso na lista de providers";
    public static final String NO_SUCH_ALGORITHM = "Algoritmo de verificação desconhecido";
    public static final String CONTENT_NOT_FOUND = "O conteúdo não pode ser encontrado pela URI indicada.";
	public static final String CERTSTORE_NULL = "O certstore do SignatureVerifier não pode ser nulo";
	public static final String MORE_THAN_ONE_DETACHED_CONTENT = "A aplicação não suporta a validação de assinaturas com mais de um conteúdo detached.";

    /**
	 * 
	 */
    private static final long serialVersionUID = 1L;

    public VerificationException(String message) {
        super(message);
    }

    public VerificationException(Throwable cause) {
        super(cause);
    }

    public VerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
