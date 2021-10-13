/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions;

import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe representa uma exceção causada quando um atributo obrigatório não
 * é encontrado em uma assinatura
 */
public class SignatureAttributeNotFoundException extends SignatureAttributeException {

    private static final long serialVersionUID = 1L;
    public static final String MISSING_MANDATED_SIGNED_ATTRIBUTE = "Atributo assinado obrigatório faltando: ";
    public static final String MISSING_MANDATED_UNSIGNED_ATTRIBUTE = "Atributo não assinado obrigatório faltando: ";
    public static final String ATTRIBUTE_NOT_FOUND = "Atributo não foi encontrado na assinatura. Identificador do atributo: ";
    public static final String MISSING_MANDATED_ATTRIBUTE = "Atributo obrigatório faltando:";
    /**
     * Identificador do atributo
     */
    private String mandatedAttributeId = "";

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public SignatureAttributeNotFoundException(String message) {
        super(message);
    }

    /**
     * Construtor usado para informar qual o atributo obrigatório que está
     * faltando.
     * @param message A mensagem de erro
     * @param mandatedAttributeId O identificador do atributo
     */
    public SignatureAttributeNotFoundException(String message, String mandatedAttributeId) {
        super(message + mandatedAttributeId);
        this.setMandatedAttributeId(mandatedAttributeId);
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    public String getMandatedAttributeId() {
        return mandatedAttributeId;
    }

    /**
     * Atribue o identificador do atributo
     * @param mandatedAttributeId O identificador do atributo
     */
    protected void setMandatedAttributeId(String mandatedAttributeId) {
        this.mandatedAttributeId = mandatedAttributeId;
    }
}
