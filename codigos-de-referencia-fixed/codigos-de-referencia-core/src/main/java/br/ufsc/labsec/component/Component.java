package br.ufsc.labsec.component;

import java.lang.reflect.Field;
import java.lang.reflect.ParameterizedType;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Abstração de um componente de uma aplicação. Deve conter os serviços providos
 * e os requisitos para poder operar.
 * 
 * Os requisitos do componente devem ser declarados como atributos públicos com
 * a anotação @Requirement.
 * 
 * Os serviços providos devem ser informados no construtor do componente através
 * da chamada do método {@link Component#defineRoleProvider(String, Object)}
 * onde o primeiro parâmetro é o nome do serviço, ou seja, o nome da interface
 * que identifica o serviço e o segundo é a implementação daquele componente
 * para o serviço em questão.
 */
public abstract class Component {

	protected Application application;
	private Map<String, Object> rolesProviders;
	private Map<String, Field> requirements;
	private int requirementsToMeet;
	private Set<String> requirementsNotMeet;

	/**
	 * Todos os componentes são criados por uma aplicação. A aplicação está dispónivel
	 * para as implementações dos componentes para que essas implementações
	 * possam acessar os parâmetros e os controles básicos da aplicação.
	 * 
	 * @param application
	 *            Instância da aplicação
	 */
	public Component(Application application) {
		this.application = application;
		this.rolesProviders = new HashMap<String, Object>();
	}

	/**
	 * Prepara a lista de requisitos do componente.
	 * 
	 * @throws IllegalAccessException
	 * @throws IllegalArgumentException
	 */
	void setupRequirements() throws IllegalArgumentException, IllegalAccessException {
		this.requirements = new HashMap<String, Field>();
		requirementsNotMeet = new HashSet<String>();
		this.requirementsToMeet = 0;
		Field[] fields = this.getClass().getDeclaredFields();
		for (Field field : fields) {
			if (field.isAnnotationPresent(Requirement.class)) {
				if (field.getType().equals(List.class)) {
					/*
					 * If we have a list, we are interested in the type that
					 * this list lists.
					 */
					ParameterizedType parameterizedType = (ParameterizedType) field.getGenericType();
					Class<?> parameterClass = (Class<?>) parameterizedType.getActualTypeArguments()[0];
					this.requirements.put(parameterClass.getName(), field);
					if (!field.getAnnotation(Requirement.class).optional()) {
						this.requirementsNotMeet.add(parameterClass.getName());
					}
					List<Object> temp = (List<Object>) field.get(this);
					if (temp != null) {
						temp.clear();
					}
				} else {
					this.requirements.put(field.getType().getName(), field);
					if (!field.getAnnotation(Requirement.class).optional()) {
						this.requirementsNotMeet.add(field.getType().getName());
					}
				}
				if (!field.getAnnotation(Requirement.class).optional()) {
					this.requirementsToMeet++;
				}
			}
		}
	}

	/**
	 * Método que deve ser usado pelas implementações de componentes para que
	 * estás definam um serviço que provém. Esse método deve ser chamado em
	 * geral no construtor da implementação do componente.
	 * 
	 * @param role
	 *            Nome do serviço provido identificado pelo nome da Interface
	 *            implementada
	 * @param provider
	 *            Implementação fornecida pelo componente
	 */
	protected final void defineRoleProvider(String role, Object provider) {
		this.rolesProviders.put(role, provider);
	}

	/**
	 * Atribui uma implementação à um campo anotado com @Requirement. O campo
	 * será identificado pelo tipo que deve ter o mesmo nome que <i>role</i>
	 * 
	 * @param role
	 *            Nome do serviço
	 * @param provider
	 *            Implementação do serviço
	 */
	public final void connect(String role, Object provider) {
		Field field = this.requirements.get(role);
		if (field != null) {
			try {
				setupField(provider, field);
				if (!field.getAnnotation(Requirement.class).optional()) {
					this.requirementsNotMeet.remove(role);
				}
			} catch (IllegalArgumentException e) {
				System.err.println("The field for role \"" + role + "\" in \"" + this.getClass()
						+ "\" couldn't be set cause the field is \n\"" + field.getType().getName()
						+ "\"\nand the object passed is \n\"" + provider.getClass() + "\".");
			} catch (IllegalAccessException e) {
				System.err.println("The field for role \"" + role + "\" is either final or inaccessible");
			}
		} else {
			System.err.println("The role \"" + role + "\" has no place to connect in \"" + this.getClass() + "\".");
		}
	}

	/**
	 * Verifica se o campo é uma lista ou não. Se não for uma lista o provider
	 * será atribuido ao campo. Se for uma lista, está será instância com o tipo
	 * {@link ArrayList} e a implementação será adicionada na lista.
	 * 
	 * @param provider
	 *            Implementação do serviço
	 * @param field
	 *            Campo para o serviço
	 * @throws IllegalAccessException
	 *             É lançada se houve problemas ao acessar o campo
	 */
	private void setupField(Object provider, Field field) throws IllegalAccessException {
		if (field.getType() == List.class) {
			List<Object> fieldAsList = (List<Object>) field.get(this);
			if (fieldAsList == null || fieldAsList.isEmpty()) {
				field.set(this, new ArrayList<Object>());
				fieldAsList = (List<Object>) field.get(this);
				if (!field.getAnnotation(Requirement.class).optional()) {
					this.requirementsToMeet--;
				}
			}
			fieldAsList.add(provider);
		} else {
			field.set(this, provider);
			if (!field.getAnnotation(Requirement.class).optional()) {
				this.requirementsToMeet--;
			}
		}
	}

	/**
	 * Método utilizado pela aplicação para obter a implementação de algum
	 * serviço. Os serviço são disponibilizados pelo método
	 * {@link Component#defineRoleProvider(String, Object)} que geralmente é
	 * chamado no construtor da Implementação do componente.
	 * 
	 * @param role
	 *            Nome do serviço buscado
	 * @return Implementação do serviço ou nulo se não houver
	 */
	public final Object getRole(String role) {
		Object roleProvider = null;
		if (this.rolesProviders.containsKey(role)) {
			roleProvider = this.rolesProviders.get(role);
		} else {
			System.err.println("Required role \"" + role + "\" not configured on component \""
					+ this.getClass().toString() + "\"\n\tRoles found: " + this.rolesProviders.keySet() );
		}

		return roleProvider;
	}

	public final Set<String> getRequirementsNotMeet() {
		return this.requirementsNotMeet;
	}

	/**
	 * Informa a aplicação se o componente está pronto para execução
	 * 
	 * @return Verdadeiro se está pronto
	 */
	public final boolean ready() {
		return this.requirementsToMeet == 0;
	}

	/**
	 * Avisa o componente que a aplicação foi configurada e está tudo pronto
	 * para começar a operação.
	 */
	public abstract void startOperation();

	/**
	 * Avisa o componente que o seu estado deve ser reiniciado
	 */
	public abstract void clear();

	/**
	 * Obtém a instância da aplicação para acessar os parâmetros ou o Logger
	 * 
	 * @return A instância da aplicação
	 */
	public Application getApplication() {
		return this.application;
	}
	
	/**
	 * Obtem a lista de interfaces providas pelo componente.
	 * 
	 * @return O conjunto.
	 */
	public Set<String> getRolesProvided() {
		return this.rolesProviders.keySet();
	}

}
