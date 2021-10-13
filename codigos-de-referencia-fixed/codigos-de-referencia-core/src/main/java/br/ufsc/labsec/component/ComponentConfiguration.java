package br.ufsc.labsec.component;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Classe para fazer a interpretação do arquivo de configuração dos componentes
 */
public class ComponentConfiguration extends AbstractComponentConfiguration {

	/**
	 * Lista adicionada para garantir que os componentes sejam criados na ordem
	 * em que foram definidos no arquivo de configuração. Útil para componentes
	 * do tipo PKCS12Repository, que precisam de uma inicialização mais complexa
	 * e é um componente do qual os outros dependem.
	 * 
	 * @param configurationFile
	 *            O {@link InputStream} do arquivo de configuração
	 */
	public ComponentConfiguration(InputStream configurationFile) {
		this.componentDependencies = new HashMap<>();
		this.componentProvides = new HashMap<>();
		this.componentProviders = new HashMap<>();
		this.connections = new HashMap<>();
		this.componentParams = new HashMap<>();

		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		try {
			DocumentBuilder documentBuilder = factory.newDocumentBuilder();
			Document document = documentBuilder.parse(configurationFile);
			this.interpretDocument(document);
		} catch (Exception e) {
			System.err.println("Erro ao fazer o parsing do arquivo de configuração: " + e.getMessage());
		}
	}
	
	/**
	 * Interpreta o documento de configuração
	 * 
	 * @param document
	 *            - O documento a ser interpretado
	 */
	protected void interpretDocument(Document document) {
		Element components = (Element) document.getElementsByTagName("components").item(0);
		NodeList componentList = components.getElementsByTagName("component");
		for (int i = 0; i < componentList.getLength(); i++) {
			Element componentDescription = (Element) componentList.item(i);
			this.interpretComponent(componentDescription);
		}
	
		Element connections = (Element) document.getElementsByTagName("connections").item(0);
		NodeList connectionList = connections.getElementsByTagName("connection");
		for (int i = 0; i < connectionList.getLength(); i++) {
			Element connection = (Element) connectionList.item(i);
			this.avaliateConnection(connection);
		}
	}

	/**
	 * Interpreta a parte da configuração de descrição de componentes
	 * 
	 * @param componentDescription
	 *            Nodo que contém a descrição de um componente
	 */
	private void interpretComponent(Element componentDescription) {
		String componentName = componentDescription.getAttribute(ATTR_NAME);
		Element dependenciesElement = (Element) componentDescription.getElementsByTagName("requires").item(0);
		if (dependenciesElement != null) {
			List<String> dependencies = this.getRoles(dependenciesElement);
			this.componentDependencies.put(componentName, dependencies);
		} else {
			System.err.println(COMPONENT_ERROR_MESSAGE + componentName + "\" has no \"requires\" list.");
			this.componentDependencies.put(componentName, new ArrayList<>());
		}
	
		Element providesElement = (Element) componentDescription.getElementsByTagName("provides").item(0);
		if (providesElement != null) {
			List<String> provides = this.getRoles(providesElement);
			this.componentProvides.put(componentName, provides);
		} else {
			System.err.println(COMPONENT_ERROR_MESSAGE + componentName + "\" has no \"provides\" list.");
			this.componentProvides.put(componentName, new ArrayList<>());
		}
	
		Element componentParams = (Element) componentDescription.getElementsByTagName("params").item(0);
		if (componentParams != null) {
			this.componentParams.put(componentName, this.getParams(componentParams));
		}
	}

	/**
	 * Obtém os parâmetros configurados para o componente identificado pelo nodo
	 * passado
	 * 
	 * @param componentParams
	 *            O nodo dos parâmetros do componente
	 * @return Um {@link Map} de nome para valor
	 */
	private Map<String, List<String>> getParams(Element componentParams) {
		Map<String, List<String>> params = new HashMap<>();
		NodeList paramsNodes = componentParams.getElementsByTagName("param");
		for (int i = 0; i < paramsNodes.getLength(); i++) {
			Element paramElement = (Element) paramsNodes.item(i);
			params.put(paramElement.getAttribute(ATTR_NAME),
					Collections.singletonList(paramElement.getAttribute("value")));
		}

		NodeList paramsListNodes = componentParams.getElementsByTagName("paramList");
		for (int i = 0; i < paramsListNodes.getLength(); i++) {
			List<String> values = new ArrayList<>();
			Element paramElement = (Element) paramsListNodes.item(i);
			NodeList valuesNodes = paramElement.getElementsByTagName("value");
			for (int j = 0; j < valuesNodes.getLength(); j++) {
				values.add(valuesNodes.item(j).getTextContent());
			}
			params.put(paramElement.getAttribute(ATTR_NAME), values);
		}

		return params;
	}

	/**
	 * Obtém os papéis do componente. O nodo passado pode ser de
	 * <i>requirement</i> ou de <i>provides</i>
	 * 
	 * @param element
	 *            Noo que contém papéis
	 * @return {@link List} com os papéis
	 */
	private List<String> getRoles(Element element) {
		List<String> roles = new ArrayList<>();
		NodeList dependenciesList = element.getElementsByTagName("role");
		for (int i = 0; i < dependenciesList.getLength(); i++) {
			Element dependency = (Element) dependenciesList.item(i);
			roles.add(dependency.getAttribute(ATTR_NAME));
		}
		return roles;
	}

	/**
	 * Verifica se os componentes tem as conexões configuradas de maneira
	 * correta. Serão avaliadas as informações contidas nos nodos
	 * <i>connection</i>. Se houver um componente que não foi
	 * 
	 * @param connection
	 *            O nodo com as informações da conexão
	 */
	private void avaliateConnection(Element connection) {
		String component = connection.getAttribute("from");
		String toComponent = connection.getAttribute("to");
		List<String> roles = this.getRoles(connection);
		List<String> dependencies = this.componentDependencies.get(component);
		if (dependencies == null) {
			Application.logger.log(Level.SEVERE,
					COMPONENT_ERROR_MESSAGE + component + COMPONENT_ERROR_NOT_IN_LIST);
		}
	
		List<String> provides = this.componentProvides.get(toComponent);
		if (provides == null) {
			Application.logger.log(Level.SEVERE,
					COMPONENT_ERROR_MESSAGE + toComponent + COMPONENT_ERROR_NOT_IN_LIST);
		}
	
		configureProviderMap(component, toComponent, roles);
	}

	/**
	 * Configura o mapa de provedores para um componente
	 * 
	 * @param component
	 *            Componente com a dependência
	 * @param toComponent
	 *            Componente com a implementação da dependência
	 * @param roles
	 *            Lista dos papéis providos por essa conexão
	 */
	private void configureProviderMap(String component, String toComponent, List<String> roles) {
		this.componentProvides.get(toComponent);
		if (!this.connections.containsKey(component)) {
			this.connections.put(component, new HashMap<>());
	
			List<String> providers = this.componentProviders.get(toComponent);
			if (providers == null) {
				providers = new ArrayList<>();
				this.componentProviders.put(toComponent, providers);
			}
	
			providers.add(component);
		}
	
		for (String role : roles) {
			setupProviderForRole(component, toComponent, role);
		}
	}

	/**
	 * Adiciona no {@link Map} de provedores de serviço o provedor para o
	 * <i>role</i> indicado.
	 * 
	 * @param component
	 *            Componente com a dependência
	 * @param toComponent
	 *            Componente com a implementação do serviço
	 * @param role
	 *            Nome do serviço
	 */
	private void setupProviderForRole(String component, String toComponent, String role) {
		Map<String, Set<String>> providerMap = this.connections.get(component);
		List<String> dependencies = this.componentDependencies.get(component);
		List<String> provides = this.componentProvides.get(toComponent);
		if (dependencies.contains(role) && provides.contains(role)) {
			if (!providerMap.containsKey(role)) {
				providerMap.put(role, new HashSet<>());
			}
			providerMap.get(role).add(toComponent);
		} else {
			System.err.println("No Role specified to connect \"" + component + "\" with \"" + toComponent + "\" on role \"" + role + "\"");
		}
	}
}