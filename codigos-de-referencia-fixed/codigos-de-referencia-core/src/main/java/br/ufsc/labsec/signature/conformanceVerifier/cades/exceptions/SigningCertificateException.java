/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions;

import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe representa uma exceção que ocorre por
 * má formação do atributo SigningCertificate
 */
public class SigningCertificateException extends SignatureAttributeException {

    public static final String INVALID_CERTIFICATE_HASH = "Um dos certificados passados no caminho de certificação "
            + "não corresponde ao seu equivalente no atributo SigningCertificate.";
    public static final String INVALID_PUBLIC_KEY_HASH = "Um dos dos SignerInfos identifica alteração na chave "
            + "pública ou utiliza um algoritmo de hash não conhecido.";
    public static final String NO_SUCH_ALGORITHM_EXCEPTION = "O algoritmo passado para gerar o hash do certificado do assinante não foi encontrado.";
    public static final String CERTIFICATE_ENCODING_EXCEPTION = "Não foi possível fazer a codificação do certificado.";

    private static final long serialVersionUID = 1L;

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public SigningCertificateException(String message) {
        super(message);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param stackTrace O stack trace da exceção que ocorreu
     */
    public SigningCertificateException(String message, StackTraceElement[] stackTrace) {
        super(message);
        this.setStackTrace(stackTrace);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param index Índice do atributo
     */
    public SigningCertificateException(String message, int index) {
        super(message + index);
    }

}
