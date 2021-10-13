/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions;

import java.io.IOException;

/**
 * Esta classe representa uma exceção causada por valor inválido
 * na política de certificação
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
     * @param stackTrace O stack trace da exceção que ocorreu
     */
    public CertificationPolicyException(String message, StackTraceElement[] stackTrace) {
        super(message);
    }

    /**
     * Construtor
     * @param cause A exceção que ocorreu
     */
    public CertificationPolicyException(IOException cause) {
        super(cause);
    }

    /**
     * Atibue o valor de crítico ao erro
     * @param critical O valor de crítico da exceção
     */
    public void setCritical(boolean critical) {
        super.setCritical(critical);
    }

}
