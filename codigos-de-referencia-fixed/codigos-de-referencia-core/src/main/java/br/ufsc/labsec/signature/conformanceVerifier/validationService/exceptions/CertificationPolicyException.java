/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.validationService.exceptions;

import java.io.IOException;

/**
 * Esta classe representa uma exceção causada quando ocorre algum erro
 * durante a validação das políticas de certificação de um cadeia de certificados
 */
public class CertificationPolicyException extends CertificationPathException {

    private static final long serialVersionUID = 1L;
    public static final String UNKNOW_CERTIFICATION_POLICY = "Política de certificação não prevista na política de assinatura. ";

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public CertificationPolicyException(String message) {
        super(message);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param stackTrace O stacktrace do erro
     */
    public CertificationPolicyException(String message, StackTraceElement[] stackTrace) {
        super(message);
    }

    /**
     * Construtor
     * @param cause A exceção que ocorreu durante a verificação
     */
    public CertificationPolicyException(IOException cause) {
        super(cause);
    }

    /**
     * Atribue se o erro é crítico
     * @param critical Indica se o erro é crítica
     */
    public void setCritical(boolean critical) {
        super.setCritical(critical);
    }

}
