/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.validationService;

import java.security.cert.CertPath;

import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa uma exceção causada por algum problema no
 * caminho de certificação de um certificado.
 */
public class CertificationPathException extends PbadException {

	private static final long serialVersionUID = 1L;

	/* Reasons for classifying a certificate as invalid */
	public static final String ALGORITHM_CONSTRAINED = "A chave pública ou o algoritmo de assinatura foram restringidos.";
	public static final String INVALID_ALGORITHM_PARAMS_OR_ALGORITHM = "Algoritmo inválido ou dados inválidos para usar o algoritmo passado para montar o caminho de certificação.";
	public static final String INVALID_KEY_USAGE = "O uso da chave do certificado é inválido.";
	public static final String INVALID_NAME = "As restrições do nome foram violadas.";
	public static final String INVALID_PATH = "Caminho de certificação inválido.";
	public static final String INVALID_POLICY = "As restrições da política foram violadas.";
	public static final String INVALID_SIGNATURE = "A assinatura é inválida.";
	public static final String INVALID_SIGNER_CERTIFICATE = "Certificado do signatário inválido.";
	public static final String INVALID_SIGNER_PATH = "Caminho de certificação do signatário inválido.";
	public static final String NAME_CHAINING = "O certificado não cria o caminho de certificação corretamente.";
	public static final String NO_SUCH_ALGORITHM = "Algoritmo desconhecido para montar o caminho de certificação.";
	public static final String NO_TRUST_ANCHOR = "Não foi encontrada uma Âncora de Confiança aceitável.";
	public static final String NOT_CA_CERT = "O certificado não é um certificado de uma AC.";
	public static final String NULL_CERT_PATH = "O caminho de certificação é nulo.";
	public static final String PATH_TOO_LONG = "As restrições do tamanho do caminho de certificação foram violadas.";
	public static final String PROBLEM_TO_VALIDATE_CERTPATH = "Caminho de certificação inválido.";
	public static final String UNDETERMINED_REVOCATION_STATUS = "Não foi possível determinar o estado da revogação.";
	public static final String UNKNOWN_CERT_PATH_VALIDATION = "Método de validação do caminho de certificação desconhecido.";
	public static final String UNRECOGNIZED_CRIT_EXT = "O certificado contém uma ou mais extensões críticas não reconhecidas.";
	public static final String CERT_PATH_NOT_FOUUND = "O Caminho de certificado não pode ser construído.";
	/*
	 * Errors with respect to this implementation that still classify the
	 * certificate as invalid
	 */
	public static final String ERROR_WHEN_SELECTING_CRL_IN_THE_CERTSTORE = "Ocorreu um erro ao selecionar as CRLs no CertStore.";
	public static final String NO_SUCH_PROVIDER = "Não foi definido o provider do BouncyCastle.";

	/* Reasons for classifying a certificate as revoked */
	public static final String REVOKED_CERTIFICATE = "O certificado está revogado.";

	/* Reasons for classifying a certificate as expired */
	public static final String EXPIRED_CERTIFICATE = "O certificado está expirado.";

	/* Reasons for classifying a certificate as not yet valid */
	public static final String CERTIFICATE_NOT_VALID_YET = "O certificado ainda não está válido.";

	/* Unspecified or unknown reason */
	public static final String UNSPECIFIED = "Não especificado.";

	public static final String CRL_NOT_FOUND = "A LCR não pode ser acessada.";

	/**
	 * Caminho de certificação
	 */
	private CertPath certPath;

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

	/**
	 * Construtor
	 * @param message A mensagem de erro
	 * @param certPath O caminho de certificação em que ocorreu o erro
	 */
	public CertificationPathException(String message, CertPath certPath) {
		super(message);
		
		this.certPath = certPath;
	}

	/**
	 * Retorna o caminho de certificação
	 * @return O caminho de certificação
	 */
	public CertPath getCertPath() {
		return this.certPath;
	}
}
