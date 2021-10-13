/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.repository.PKCS12IdentityService.exceptions;

import java.io.IOException;

public class CertificationPolicyException extends CertificationPathException {

    /**
	 * 
	 */
    private static final long serialVersionUID = 1L;
    public static final String UNKNOW_CERTIFICATION_POLICY = "Política de certificação não prevista na política de assinatura. ";

    public CertificationPolicyException(String message) {
        super(message);
    }

    public CertificationPolicyException(String message, StackTraceElement[] stackTrace) {
        super(message);
    }

    public CertificationPolicyException(IOException cause) {
        super(cause);
    }

    public void setCritical(boolean critical) {
        super.setCritical(critical);
    }

}
