package br.ufsc.labsec.component;

import java.lang.reflect.Field;
import java.lang.reflect.ParameterizedType;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Esta classe engloba os métodos de configuração de componentes
 */
public class AbstractComponentConfiguration {

	protected static final String COMPONENT_ERROR_NOT_IN_LIST = "\" isn't in the component list.";
	protected static final String COMPONENT_ERROR_MESSAGE = "The component \"";
	protected static final String ATTR_NAME = "name";
	protected Map<String, List<String>> componentDependencies;
	protected Map<String, List<String>> componentProvides;
	protected Map<String, List<String>> componentProviders;

	// componente, nome do parâmetro, valor do parâmetro
	protected Map<String, Map<String, List<String>>> componentParams;

	protected Map<String, Map<String, Set<String>>> connections;
	protected static AbstractComponentConfiguration instance;
	private Class<? extends Component> component;

	protected AbstractComponentConfiguration() {
		AbstractComponentConfiguration.instance = this;
		this.componentDependencies = new HashMap<>();
		this.componentProvides = new HashMap<>();
		this.componentProviders = new HashMap<>();
		this.connections = new HashMap<>();
		this.componentParams = new HashMap<>();
	}

	/**
	 * Obtém a lista de componentes presentes no arquivo de configuração
	 *
	 * @return Uma {@link List} com os nomes do componente.
	 */
	public List<String> getComponents() {
		return new ArrayList<>(this.componentProvides.keySet());
	}

	/**
	 * Obtém a lista de dependências do componente.
	 *
	 * @param componentName
	 *            Nome do componente do qual se quer a lista de dependências
	 * @return Uma {@link List} com os nomes das dependências.
	 */
	public List<String> getDependencies(String componentName) {
		List<String> result = null;
		if (this.componentDependencies.containsKey(componentName)) {
			result = new ArrayList<>(this.componentDependencies.get(componentName));
		}
		return result;
	}

	/**
	 * Obtém o conjunto de serviços providos para o componente.
	 *
	 * @param componentName
	 u            Nome do componente que depende do serviço
	 * @param role
	 *            Nome do serviço
	 * @return Um {@link Set} com os componentes que provém o serviço para esse
	 *         componente.
	 */
	public Set<String> getProviders(String componentName, String role) {
		Set<String> result = null;
		if (this.connections.containsKey(componentName) && this.connections.get(componentName).containsKey(role)) {
			result = this.connections.get(componentName).get(role);
		}
		return result;
	}

	/**
	 * Obtém o valor para um parâmetro de um dado componente.
	 *
	 * @param componentName
	 *            Nome do componente do qual se quer os parâmetros
	 * @param paramName
	 *            Nome do parâmetro
	 * @return O valor do parâmetro em forma de {@link String}
	 */
	public String getComponentParam(String componentName, String paramName) {
		Map<String, List<String>> componentParams = this.componentParams.get(componentName);
		if (componentParams != null) {
			return componentParams.get(paramName).get(0);
		}
		return null;
	}

	/**
	 * Obtém o valor para um parâmetro de um dado componente.
	 *
	 * @param componentName
	 *            Nome do componente do qual se quer os parâmetros
	 * @param paramName
	 *            Nome do parâmetro
	 * @return O valor do parâmetro em forma de {@link String}
	 */
	public List<String> getComponentParams(String componentName, String paramName) {
		Map<String, List<String>> componentParams = this.componentParams.get(componentName);
		if (componentParams != null) {
			return componentParams.get(paramName);
		}
		return null;
	}

	/**
	 * Redefine um parâmetro do componente ou o cria.
	*/
	public void setComponentParam(String componentName, String paramName, String paramValue) {
		Map<String, List<String>> componentParams = this.componentParams.get(componentName);
		if (componentParams == null) {
			componentParams = new HashMap<>();
		}
		componentParams.put(paramName, Collections.singletonList(paramValue));

		this.componentParams.put(componentName, componentParams);
	}

	public void replaceComponent(String oldComponent, String newComponent) {
		List<String> values = this.componentDependencies.get(oldComponent);
		if (values != null) {
			this.componentDependencies.put(newComponent, values);
			this.componentDependencies.remove(oldComponent);
		}

		for (String key : this.componentDependencies.keySet()) {
			if (this.componentDependencies.get(key).contains(oldComponent)) {
				this.componentDependencies.get(key).add(newComponent);
				this.componentDependencies.get(key).add(oldComponent);
			}
		}

		values = this.componentProviders.get(oldComponent);
		if (values != null) {
			this.componentProviders.put(newComponent, values);
			this.componentProviders.remove(oldComponent);
		}

		for (String key : this.componentProviders.keySet()) {
			if (this.componentProviders.get(key).contains(oldComponent)) {
				this.componentProviders.get(key).add(newComponent);
				this.componentProviders.get(key).add(oldComponent);
			}
		}

		values = this.componentProvides.get(oldComponent);
		if (values != null) {
			this.componentProvides.put(newComponent, values);
			this.componentProvides.remove(oldComponent);
		}

		for (String key : this.componentProvides.keySet()) {
			if (this.componentProvides.get(key).contains(oldComponent)) {
				this.componentProvides.get(key).add(newComponent);
				this.componentProvides.get(key).add(oldComponent);
			}  // TODO check if the above loops are working as expected.
		}

		Map<String, Map<String, Set<String>>> tempToPut = new HashMap<>();
		Set<String> tempToRemove = new HashSet<>();

		for (String key : this.connections.keySet()) {
			Map<String, Set<String>> map = this.connections.get(key);
			for (String otherKey : map.keySet()) {
				Set<String> set = map.get(otherKey);
				if (set.contains(oldComponent)) {
					set.add(newComponent);
					set.remove(oldComponent);
				}
			}
			if (key.compareTo(oldComponent) == 0) {
				tempToPut.put(newComponent, this.connections.get(oldComponent));
				tempToRemove.add(oldComponent);
			}
		}

		for (String toRemove : tempToRemove) {
			this.connections.remove(toRemove);
		}

		for (String toPut : tempToPut.keySet()) {
			this.connections.put(toPut, tempToPut.get(toPut));
		}
	}

	private Class<? extends Component> connector;

	public static AbstractComponentConfiguration getInstance() {
		return instance;
	}

	/**
	 * Define um component que receberá uma conexão
	 *
	 * @param componentClass
	 *            A classe do componente
	 * @return A própria configuração de componentes atualizada
	 */
	public AbstractComponentConfiguration component(Class<? extends Component> componentClass) {
		if (componentClass == null) {
			System.err.println("Parâmetro nulo.");
		} else {
			this.component = componentClass;
		}
		return this;
	}

	/**
	 * Define qual o componente que será conectado para prover o serviço
	 * necessário
	 *
	 * @param componentClass
	 *            Classe do componente provedor do serviço
	 * @return A própria configuração de componentes atualizada
	 */
	public AbstractComponentConfiguration connect(Class<? extends Component> componentClass) {
		if (this.component == null) {
			System.err.println("Você precisa definir primeiro um componente que receberá a conexão.");
			return this;
		}

		if (componentClass != null) {
			this.connector = componentClass;
		} else {
			System.err.println("Parâmetro nulo.");
		}
		return this;
	}

	/**
	 * O papel em qual deve ser executada a conexão
	 *
	 * @param role
	 *            A classe do papel da conexão
	 * @return A própria configuração de componentes atualizada
	 */
	public AbstractComponentConfiguration on(Class<?> role) {
		if (role == null) {
			System.err.println("Parâmetro nulo.");
			return this;
		}

		if (this.component == null) {
			System.err.println("Você precisa definir primeiro um componente que receberá a conexão.");
			return this;
		}

		if (this.connector == null) {
			System.err.println("Você precisa definir primeiro um componente que proverá o serviço.");
			return this;
		}

		this.componentDependencies(this.component);
		this.componentDependencies(this.connector);
		this.setupReceiver(this.component);
		this.setupProvider(this.connector, role);
		this.setupConnection(this.component, this.connector, role);

		return this;
	}

	/**
	* This method is responsible for handling the contents that might be stored
	* inside the "componentParams" attribute.
	 *
	 * 1. {@code Map<String, Map<String, List<String>>>} We get map inside the map.
	 * 2. Check if it is null; if it is, we initialize and add something inside it.
	 * 3. Finally, we put a key and content to be linked to that same key;
	 * that content will be a list with only one element, a singleton list.
	 *
	 * @return AbstractComponentConfiguration
	*/
	public AbstractComponentConfiguration param(String name, String value) {
		Map<String, List<String>> params = this.componentParams.get(this.component.getName());
		if (params == null) {
			params = new HashMap<>();
			this.componentParams.put(this.component.getName(), params);
		}

		params.put(name, Collections.singletonList(value));
		return this;
	}

	/**
	* Pretty much the same thing as above; at the end of the method, though,
	 * we do not create a singleton list.
	 *
	 * 1. {@code Map<String, Map<String, List<String>>>} We get map inside the map.
	 * 2. Check if it is null; if it is, we add something inside it.
	 * 3. We get the List<String> from "params".
	 * 4. We check if it is null; if it is, we initialize it.
	 * 5. We add the "value" inside the "values" list.
	 * 6. Finally, we put the the "values" list linked to the "name" key
	 * inside "params".
	 *
	 * NOTE:
	 * 	See, this method, as it is called, appends objects to a list.
	 * 	If it starts as an empty/null list, we initialize it first and
	 * 	we get to append content to that same list every time this method
	 * 	is called.
	 *
	 * @return AbstractComponentConfiguration
	*/
	public AbstractComponentConfiguration paramAppend(String name, String value) {
		Map<String, List<String>> params = this.componentParams.get(this.component.getName());
		if (params == null) {
			params = new HashMap<>();
			this.componentParams.put(this.component.getName(), params);
		}

		List<String> values = params.get(name);
		if (values == null)
			values = new ArrayList<>();
		values.add(value);

		params.put(name, values);
		return this;
	}

	/**
	* @param component A component that is a subclass object of the Component class,
	 *                 or a Component class object itself.
	*/
	private void componentDependencies(Class<? extends Component> component) {
		if (!this.componentDependencies.containsKey(component.getName())) {
			List<String> requirements = new ArrayList<>();
			Field[] fields = component.getDeclaredFields();
			for (Field field : fields) {
				Requirement requirement = field.getAnnotation(Requirement.class);
				if (requirement != null && !requirement.optional()) {
					if (field.getType().equals(List.class)) {
						ParameterizedType parameterizedType = (ParameterizedType) field.getGenericType();
						Class<?> parameterClass = (Class<?>) parameterizedType.getActualTypeArguments()[0];
						requirements.add(parameterClass.getName());
					} else {
						requirements.add(field.getType().getName());
					}
				}
			}
			this.componentDependencies.put(component.getName(), requirements);
		}
	}

	/**
	 * Sets the receiver. Using the "computeIfAbsent" method, we can check if there are
	 * any values linked to the key "component.getName()". If there is not, we
	 * then execute a function, passed as an argument; in this case, will
	 * be building a new string array list.
	 *
	 * No need for local variables; the return is placed inside the map
	 * that calls the method; in this case, it will be "componentProvides".
	 *
	 * @param component A component that is a subclass object of the Component class,
	 *                  or a Component class object itself.
	 */
	private void setupReceiver(Class<? extends Component> component) {
		this.componentProvides.computeIfAbsent(component.getName(), k -> new ArrayList<>());
	}

	/**
	 * Sets the provider. Using the "computeIfAbsent" method, we can check if there are
	 * any values linked to the key "connector.getName()". If there is not, we
	 * then execute a function, passed as an argument; in this case, will
	 * be building a new string array list.
	 *
	 * Then, at last, we do need only to check if the "provided" has a provider, which
	 * is represented as "role". If there isn't a provider for the provided, we must add
	 * it. Else, we do nothing, because there ir already a provider for the provided.
	 *
	 * @param connector A component that is a subclass object of the Component class,
	 *                  or a Component class object itself.
	 * @param role 		The provider.
	 */
	private void setupProvider(Class<? extends Component> connector, Class<?> role) {
		List<String> provided = this.componentProvides.computeIfAbsent(connector.getName(), k -> new ArrayList<>());
		if (!provided.contains(role.getName())) {
			provided.add(role.getName());
		}
	}

	/**
	 * Sets the connection. Step one is using the "computeIfAbsent" method, we can check if there are
	 * any values linked to the key "component.getName()". If there is not, we
	 * then execute a function, passed as an argument; in this case, will
	 * be building a new string array list.
	 *
	 * If the "providers" does not contains the connector, we shall add it.
	 *
	 * Then, we repeat the step one twice: one for the connections, and, secondly,
	 * to the set that resides inside "connections" variable. Thirdly,
	 * we add the connector inside the recently created Set<String>.
	 *
	 * Last step, divided in other a few steps, should be like this, then:
	 * 	1. If the component is not yet inside the dependencies of this component
	 * 	we are using, we add it.
	 * 	2. Or else, we do know that the one of the component dependencies is
	 * 	"component". We check if the List<String> inside the Map<String, List<String>>
	 * 	has the role of that component that we know that exists.
	 * 		2.1 If there is no role for that component, we give one to it.
	 *
	 * @param component The component that we will be handling here. We must use it as
	 *                  the stepping stone for calling the methods that will, directly,
	 *                  create the local variables we must use here.
	 * @param connector Will be connecting the component to its role.
	 * @param role      The role of the given component.
	 */
	private void setupConnection(Class<? extends Component> component, Class<? extends Component> connector, Class<?> role) {
		List<String> providers = this.componentProviders.computeIfAbsent(component.getName(), k -> new ArrayList<>());
		if (!providers.contains(connector.getName())) {
			providers.add(connector.getName());
		}

		Map<String, Set<String>> connections = this.connections.computeIfAbsent(component.getName(), k -> new HashMap<>());
		Set<String> connectionsByRole = connections.computeIfAbsent(role.getName(), k -> new HashSet<>());
		connectionsByRole.add(connector.getName());

		if (!this.componentDependencies.containsKey(component.getName())) {
			List<String> dependencies = new ArrayList<>();
			dependencies.add(role.getName());
			this.componentDependencies.put(connector.getName(), dependencies);
		} else {
			List<String> dependencies = this.componentDependencies.get(component.getName());
			if (!dependencies.contains(role.getName()))
				dependencies.add(role.getName());
		}
	}

	protected void run(String[] args) {
		Components.run(args);
	}

}
