package br.ufsc.labsec.component;

import java.util.*;

/**
 * Esta classe é responsável pela configuração do componente de inicialização dos sistemas.
 * É utilizada nos testes do Verificador e do Assinador.
 */
public class JoinedComponentConfiguration extends AbstractComponentConfiguration {

    /**
     * Construtor
     * @param configurations Lista de configurações de componentes que se deseja adicionar
     */
    public JoinedComponentConfiguration(List<AbstractComponentConfiguration> configurations) {
        super();
        for (AbstractComponentConfiguration configuration : configurations) {
            insertListStrMap(configuration.componentDependencies, this.componentDependencies);
            insertListStrMap(configuration.componentProvides, this.componentProvides);
            insertListStrMap(configuration.componentProviders, this.componentProviders);
            insertComposedMapWithSet(configuration.connections, this.connections);
            insertComposedMapWithList(configuration.componentParams, this.componentParams);
        }
    }

    /**
     * Adiciona os elementos de um mapa a outro
     * @param map O mapa cujo elementos serão copiados
     * @param into O mapa onde os elementos serão adicionados
     */
    private void insertComposedMapWithSet(Map<String, Map<String, Set<String>>> map, Map<String, Map<String, Set<String>>> into) {
        for (Object key : map.keySet().toArray()) {
            if (!into.containsKey(key)) {
                into.put((String) key, map.get(key));
            } else {
                insertSetStrMap(map.get(key), into.get(key));
            }
        }
    }

    /**
     * Adiciona os elementos de um mapa a outro
     * @param map O mapa cujo elementos serão copiados
     * @param into O mapa onde os elementos serão adicionados
     */
    private void insertComposedMapWithList(Map<String, Map<String, List<String>>> map, Map<String, Map<String, List<String>>> into) {
        for (Object key : map.keySet().toArray()) {
            if (!into.containsKey(key)) {
                into.put((String) key, map.get(key));
            } else {
                insertListStrMap(map.get(key), into.get(key));
            }
        }
    }

    /**
     * Adiciona os elementos de um mapa a outro
     * @param map O mapa cujo elementos serão copiados
     * @param into O mapa onde os elementos serão adicionados
     */
    private void insertListStrMap(Map<String, List<String>> map, Map<String, List<String>> into) {
        for (Object key : map.keySet().toArray()) {
            if (!into.containsKey(key)) {
                into.put((String) key, map.get(key));
            } else {
                List<String> fromList = map.get(key);
                List<String> intoList = into.get(key);

                insertStringCollection(fromList, intoList);
            }
        }
    }

    /**
     * Adiciona os elementos de um mapa a outro
     * @param map O mapa cujo elementos serão copiados
     * @param into O mapa onde os elementos serão adicionados
     */
    private void insertSetStrMap(Map<String, Set<String>> map, Map<String, Set<String>> into) {
        for (Object key : map.keySet().toArray()) {
            if (!into.containsKey(key)) {
                into.put((String) key, map.get(key));
            } else {
                Set<String> fromSet = map.get(key);
                Set<String> intoSet = into.get(key);

                intoSet.addAll(fromSet);
            }
        }
    }

    /**
     * Adiciona os elementos de uma coleção à outra, sem repetir
     * @param col Elementos a serem adicionados
     * @param into Coleção onde os elementos serão adicionados
     */
    private void insertStringCollection(Collection<String> col, Collection<String> into) {
        for (String str : col) {
            if (!into.contains(str)) {
                into.add(str);
            }
        }
    }
}
