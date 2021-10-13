package br.ufsc.labsec.signature.signer;

/**
 * Enumera os modos de assinatura possíveis
 */
public enum FileFormat {
    ATTACHED("attached"),
    DETACHED("detached"),
    ENVELOPED("enveloped"),
    INTERNALLY_DETACHED("internally_detached");

    /**
     * Modo de assinatura selecionado
     */
    private String str;

    /**
     * Construtor
     * @param str Modo de assinatura selecionado
     */
    FileFormat(String str) {
        this.str = str;
    }

    /**
     * Retorna o modo de assinatura selecionado
     * @return Modo de assinatura selecionado
     */
    @Override
    public String toString() {
        return this.str;
    }
}