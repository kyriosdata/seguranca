package br.ufsc.labsec.signature;

import java.util.HashMap;
import java.util.Map;

/**
 * Essa classe é utilizada para configurar atributos que necessitam de
 * configuração.
 */
public class AttributeParams {

    private Map<String, String> params;

    public AttributeParams() {
        params = new HashMap<String, String>();
    }

    public void setParam(String name, String value) {
        params.put(name, value);
    }

    public String getParam(String name) {
        return params.get(name);
    }
}
