/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.exceptions;

public class PbadException extends Exception {

    /**
	 * 
	 */
    private static final long serialVersionUID = 1L;
    public static final String INVALID_SIGNATURE = "A assinatura não está íntegra";
    public static final String NO_SUCH_ALGORITHM = "Algoritmo desconhecido";
    private boolean critical = true;

    public PbadException(String message) {
        super(message);
    }

    public PbadException(Throwable cause) {
        super(cause);
    }

    public PbadException(String message, Throwable cause) {
        super(message, cause);
    }

    protected void setCritical(boolean critical) {
        this.critical = critical;
    }

    public boolean isCritical() {
        return this.critical;
    }
}
