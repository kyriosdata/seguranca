package br.ufsc.labsec.signature.conformanceVerifier.pades.attributes;

import br.ufsc.labsec.signature.conformanceVerifier.report.AttribReport;
import br.ufsc.labsec.signature.exceptions.NotInICPException;

/**
 * Esta interface engloba métodos comuns aos atributos
 * de assinaturas PAdES.
 */
public interface PadesAttribute {

    /**
     * Valida o atributo e adiciona o resultado ao relatório dado
     * @param report O relatório do atributo que será validado
     * @return Indica se o atributo é válido
     */
    boolean validate(AttribReport report) throws NotInICPException;

}
