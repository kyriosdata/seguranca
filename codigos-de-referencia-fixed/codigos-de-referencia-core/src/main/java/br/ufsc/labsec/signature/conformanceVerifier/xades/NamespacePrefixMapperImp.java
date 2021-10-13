/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.util.HashMap;
import java.util.Map;

import com.sun.xml.bind.marshaller.NamespacePrefixMapper;

/**
 * Esta classe faz o mapeamento das URIs referentes às estruturas em que cada
 * atributo da assinatura pertence, com o nome desta estrutura.
 */
public class NamespacePrefixMapperImp extends NamespacePrefixMapper {

    public static final String LPA_NS = "http://www.iti.gov.br/LPA#";
    public static final String PA_NS = "http://www.iti.gov.br/PA#";
    public static final String XADES_NS = "http://uri.etsi.org/01903/v1.3.2#";
    public static final String XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
    public static final String XADESv141_NS = "http://uri.etsi.org/01903/v1.4.1#";
    /**
     * Mapa entre namespaces e seus respectivos prefixos
     */
    private Map<String, String> namespacesPrefixesMap;

    /**
     * Construtor. Cria um mapa onde são relacionadas as URIs referentes às estruturas
     * a qual cada objeto da assinatura pertence com o objeto criado em si
     */
    public NamespacePrefixMapperImp() {
        namespacesPrefixesMap = new HashMap<String, String>();
        namespacesPrefixesMap.put(XMLDSIG_NS, "ds");
        namespacesPrefixesMap.put(XADES_NS, "XAdES");
        namespacesPrefixesMap.put(PA_NS, "pa");
        namespacesPrefixesMap.put(LPA_NS, "lpa");
    }

    /**
     * Seleciona o namespace usado na construção do objeto XML e o transforma para
     * um padrão definido pelo usuário
     * @param namespaceUri O namespace usado na construção do objeto XML
     * @param sugestion O novo padrão de namespace
     * @param arg2
     * @return O novo prefixo padrão
     */
    @Override
    public String getPreferredPrefix(String namespaceUri, String sugestion, boolean arg2) {
        String prefix = namespacesPrefixesMap.get(namespaceUri);

        if (prefix == null)
            prefix = sugestion;

        return prefix;
    }

}
