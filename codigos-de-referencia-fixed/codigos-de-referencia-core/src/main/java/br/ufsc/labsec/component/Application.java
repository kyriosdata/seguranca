package br.ufsc.labsec.component;

import br.ufsc.labsec.signature.SignatureDataWrapper;

import java.awt.Dimension;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.ErrorManager;
import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import javax.swing.JApplet;
import javax.swing.JFrame;
import javax.swing.JMenuBar;
import javax.swing.JPanel;

/**
 * Representa a aplicação que é composta por componentes. Contém também o
 * suporte para o acesso aos parâmetros da aplicação e dos componentes.
 */
public class Application {

	public static Logger logger;
	static {
		Application.logger = Logger.getLogger(Application.class.getName());
		try {
			Application.logger.addHandler(new DatedFileHandler("Application"));
		} catch (SecurityException e) {
			System.err.println("Log file initialization failed. " + e.getMessage());
		}
	}
	public static Logger loggerInfo;
	static {
		loggerInfo = Logger.getLogger("LoggerInfo");
		try {
			Application.loggerInfo.addHandler(new DatedFileHandler("Logger"));
		} catch (SecurityException e) {
			System.err.println("Log file initialization failed. " + e.getMessage());
		}
	}

	/**
	 * Esta classe lida com a escrita de arquivos
	 */
	static public class DatedFileHandler extends Handler {
		
		private final String baseName;
		private final String basePath;

		DatedFileHandler(String baseName) {
			super();
			this.baseName = baseName;
			this.basePath = "";
		}
		
	    @Override
	    public synchronized void publish(LogRecord r) {
	        if (isLoggable(r)) {
	            try {
	                FileHandler h = new FileHandler(fileName(r), 0, 1, true);
	                try {
	                    h.setLevel(getLevel());
	                    h.setEncoding(getEncoding());
	                    h.setFormatter(new SimpleFormatter());
	                    h.setFilter(getFilter());
	                    h.setErrorManager(getErrorManager());
	                    h.publish(r);
	                } finally {
	                    h.close();
	                }
	            } catch (IOException | SecurityException jm) {
	                this.reportError(null, jm, ErrorManager.WRITE_FAILURE);
	            }
	        }
	    }
	
	    @Override
	    public void flush() {
	    }
	
	    @Override
	    public void close() {
	        super.setLevel(Level.OFF);
	    }
	
	    private String fileName(LogRecord r) {
	        String data = new SimpleDateFormat("yyyyMMdd").format(new Date(r.getMillis()));
			return basePath + baseName + "-" + data + ".log";
	    }
	}

	
	private static final String CANNOT_BE_FOUND = "\" cannot be found.";
	private static final String THE_INSTANCE_FOR = "The instance for \"";

	private final AbstractComponentConfiguration componentConfiguration;
	private Map<String, Component> components;
	private Map<String, String> applicationParameters;
	private JFrame mainWindow;
	private JApplet mainWindowApplet;
	private List<SignatureDataWrapper> signatureWrapperList;

	/**
	 * Inicializador da aplicação. Os parâmetros recebidos em main devem ser
	 * passados como <i>args</i>. O primeiro argumento sempre deve ser o
	 * endereço de onde está o arquivo de configuração dos componentes.
	 * 
	 * @param args
	 *            - argumentos da aplicação.
	 * @see ComponentConfiguration
	 */
	public Application(String[] args) {
		this.componentConfiguration = AbstractComponentConfiguration.getInstance();

		this.applicationParameters = new HashMap<>();
		if (args.length > 1) {
			for (int i = 0; i < args.length - 1; i = i + 2) {
				this.applicationParameters.put(args[i], args[i + 1]);
			}
		}
	}

	/**
	 * Inicializador da aplicação.
	 * 
	 * @param configurationPath
	 *            - caminho do arquivo de configuração da aplicação
	 * @param applet
	 *            - instancia do applet presente na página da aplicação.
	 */
	public Application(String configurationPath, JApplet applet) {
		this.mainWindowApplet = applet;
		InputStream configurationStream = Application.class.getResourceAsStream(configurationPath);
		this.componentConfiguration = new ComponentConfiguration(configurationStream);
		this.applicationParameters = new HashMap<>();
	}

	public Application() {
		this.mainWindow = new JFrame();
		this.componentConfiguration = AbstractComponentConfiguration.getInstance();
		this.applicationParameters = new HashMap<>();
	}

	/**
	 * Inicializador da aplicação.
	 * 
	 * @param configurationPath
	 *            - caminho do arquivo de configuração da aplicação
	 * @throws FileNotFoundException
	 *             É lançada se o arquivo de configuração não for encontrado.
	 */
	public Application(String configurationPath) throws FileNotFoundException {
		InputStream configurationStream = new FileInputStream(configurationPath);
		this.componentConfiguration = new ComponentConfiguration(configurationStream);
		this.applicationParameters = new HashMap<>();
	}

	public Application(InputStream signature, InputStream detached, String filename) {
		if (this.signatureWrapperList == null) {
			this.signatureWrapperList = new ArrayList<>();
		}
		this.componentConfiguration = AbstractComponentConfiguration.getInstance();
		this.signatureWrapperList.add(new SignatureDataWrapper(signature, detached, filename));
	}

	public Application(AbstractComponentConfiguration componentConfiguration, InputStream signature, InputStream detached, String filename) {
		if (this.signatureWrapperList == null) {
			this.signatureWrapperList = new ArrayList<>();
		}
		this.componentConfiguration = componentConfiguration;
		this.signatureWrapperList.add(new SignatureDataWrapper(signature, detached, filename));
	}

	public Application(List<SignatureDataWrapper> signatureWrapperList) {
		this.componentConfiguration = AbstractComponentConfiguration.getInstance();
		this.signatureWrapperList = signatureWrapperList;
	}

	public Application(AbstractComponentConfiguration componentConfiguration, List<SignatureDataWrapper> signatureWrapperList) {
		this.componentConfiguration = componentConfiguration;
		this.signatureWrapperList = signatureWrapperList;
	}

	/**
	 * Instancia e conecta os componentes.
	 * 
	 * @return Verdadeiro se os componentes foram inicializados com sucesso.
	 */
	public boolean setup() {
		/*
		 * Load and connect the components
		 */
		this.components = new HashMap<>();
		instantiateComponents(components);
		/*
		 * Connect them
		 */
		return setupInitialConnections(components);
	}

	/**
	 * Conecta os componentes com os seus requisitos. E verifica se os
	 * requisitos todos foram satisfeitos. Se as conexões estão prontas o método
	 * startOperation(...).
	 * 
	 * @param components
	 *            Mapa de componentes de <b>"Nome"</b> -> <b> "Instância" </b>
	 * @return Verdadeiro se as conexões foram feitas com sucesso e os
	 *         requisitos satisfeitos.
	 */
	private boolean setupInitialConnections(Map<String, Component> components) {
		Iterator<Component> i;
		boolean ready = connectAndCheck(components);

		if (ready) {
			i = components.values().iterator();
			while (i.hasNext()) {
				Component component = i.next();
				component.startOperation();
			}
		}

		return ready;
	}

	/**
	 * Conecta os componentes com os seus requisitos e verifica se os requisitos
	 * todos foram satisfeitos.
	 * 
	 * @param components
	 *            Mapa de componentes de <b>"Nome"</b> -> <b> "Instância" </b>
	 * @return Verdadeiro se as conexões foram feitas com sucesso e os
	 *         requisitos satisfeitos.
	 */
	private boolean connectAndCheck(Map<String, Component> components) {
		if (!connect(components)) {
			return false;
		}

		boolean ready = check(components);
		return ready;
	}

	/**
	 * Conecta os componentes com os seus requisitos.
	 * 
	 * @param components
	 *            Mapa de componentes de <b>"Nome"</b> -> <b> "Instância" </b>
	 * @return Verdadeiro se as conexões foram feitas com sucesso
	 */
	private boolean check(Map<String, Component> components) {
		Iterator<Component> i = components.values().iterator();
		boolean ready = true;
		while (i.hasNext() && ready) {
			Component component = i.next();
			ready &= component.ready();
			if (!component.ready()) {
				System.err.println("The component \"" + component.getClass() + "\" isn't ready.");
				System.err.println("Requirements names: " + component.getRequirementsNotMeet());

			}
		}
		return ready;
	}

	/**
	 * Verifica se os requisitos todos foram satisfeitos.
	 * 
	 * @param components
	 *            Mapa de componentes de <b>"Nome"</b> -> <b> "Instância" </b>
	 * @return Verdadeiro se os foram requisitos satisfeitos.
	 */
	private boolean connect(Map<String, Component> components) {
		for (String componentName : components.keySet()) {
			List<String> roles = this.componentConfiguration.getDependencies(componentName);
			for (String role : roles) {
				if (!makeConnections(components, componentName, role)) {
					return false;
				}
			}
		}

		return true;
	}

	/**
	 * Connecta o component <i>componentName</i> com o provedor do serviço
	 * indicado por <i>role</i>
	 * 
	 * @param components
	 *            Mapa de componentes de <b>"Nome"</b> -> <b> "Instância" </b>
	 * @param componentName
	 *            Nome do componente que será conectado
	 * @param role
	 *            Nome do serviço necessitado
	 * @return Verdadeiro se a conexão foi encontrada e feita com sucesso
	 */
	private boolean makeConnections(Map<String, Component> components, String componentName, String role) {
		Set<String> providers = this.componentConfiguration.getProviders(componentName, role);
		if (providers == null) {
			System.err.println("Provider for role \"" + role + "\" on component \"" + componentName + "\" not specified.");
			return false;
		}

		for (String providerName : providers) {
			Component provider = components.get(providerName);
			Component required = components.get(componentName);
			if (provider != null) {
				Object providerInterface = provider.getRole(role);
				if (providerInterface != null) {
					if (required != null) {
						required.connect(role, providerInterface);
					} else {
						System.err.println(THE_INSTANCE_FOR + componentName + CANNOT_BE_FOUND);
					}
				} else {
					System.err.println(THE_INSTANCE_FOR + role + "\" on \"" + providerName + CANNOT_BE_FOUND);
				}
			} else {
				System.err.println(THE_INSTANCE_FOR + providerName + CANNOT_BE_FOUND);
			}
		}

		return true;
	}

	/**
	 * Instância os componentes.
	 * 
	 * @param components
	 *            Mapa de componentes de <b>"Nome"</b> -> <b> "Instância" </b>
	 */
	private void instantiateComponents(Map<String, Component> components) {
		for (String componentClassName : this.componentConfiguration.getComponents()) {

			Class<? extends Component> componentClass = null;
			try {
				componentClass = (Class<? extends Component>) Class.forName(componentClassName);
			} catch (ClassNotFoundException e) {
				Application.logger.log(Level.SEVERE, "Component not found: \\" + componentClassName + "\\", e);
			}

			if (componentClass != null) {
				Constructor<? extends Component> constructor = obtainConstructor(componentClass);

				putInTheMap(components, componentClassName, constructor);

			}
		}
	}

	/**
	 * Constrói o componente e o coloca no {@link Map}
	 * 
	 * @param components
	 *            Mapa de componentes de <b>"Nome"</b> -> <b> "Instância" </b>
	 * @param componentClassName
	 *            nome do componente
	 * @param constructor
	 *            construtor
	 */
	private Component putInTheMap(Map<String, Component> components, String componentClassName,
								  Constructor<? extends Component> constructor) {
		Component result = null;
		try {
			result = constructor.newInstance(this);
			result.setupRequirements();
			components.put(componentClassName, result);
		} catch (Exception e) {
			Application.logger.log(Level.SEVERE, "Erro ao instânciar o componente.", e);
		}

		return result;
	}

	/**
	 * Obtém o construtor do componente
	 * 
	 * @param componentClass
	 *            Nome do componente
	 * @return o construtor para o componente representado por
	 *         {@link Constructor}
	 */
	private Constructor<? extends Component> obtainConstructor(Class<? extends Component> componentClass) {
		Constructor<? extends Component> constructor = null;
		try {
			constructor = componentClass.getConstructor(new Class<?>[] { Application.class });
		} catch (NoSuchMethodException e) {
			Application.logger.log(Level.SEVERE,
					"O componente não fornece um construtor do tipo \"Componente(Application app)\".", e);
		}
		return constructor;
	}

	/**
	 * Método para acessar os parâmetros passados para a aplicação.
	 * 
	 * @param parameterName
	 *            Nome do parâmetro. Os parâmetros são considerados em pares nome-valor
	 * @return Retorna o valor do parâmtro
	 */
	public String getParameter(String parameterName) {
		if (this.applicationParameters == null) {
			return null;
		}
		return this.applicationParameters.get(parameterName);
	}

	/**
	 * Encerra a execução da aplicação
	 */
	public void terminate() {
		System.exit(0);
	}

	/**
	 * Retorna um parâmetro especifico para algum componente
	 * 
	 * @param component
	 *            Nome do componente
	 * @param name
	 *            Nome do parâmetro
	 * @return Valor do parâmetro
	 */
	public String getComponentParam(Component component, String name) {
		return this.componentConfiguration.getComponentParam(component.getClass().getName(), name);
	}

	/**
	 * Retorna uma lista de parâmetros específicos para algum componente
	 *
	 * @param component
	 *            Nome do componente
	 * @param name
	 *            Nome do parâmetro
	 * @return Valor do parâmetro
	 */
	public List<String> getComponentParams(Component component, String name) {
		return this.componentConfiguration.getComponentParams(component.getClass().getName(), name);
	}

	public List<SignatureDataWrapper> getSignatureWrapperList() {
		return this.signatureWrapperList;
	}

	/**
	 * Trata uma exceção ocorrida em um componente. O erro será repassado para
	 * os componentes registrados como tratadores de erros e os demais
	 * componentes serão reiniciados para que o erro não faça com que os
	 * componentes fiquem em algum estado inválido.
	 * 
	 * @param e
	 *            O erro que ocorreu
	 */
	public void reportError(Exception e) {
		this.callHandlers(e);
		this.resetStates();
	}

	/**
	 * Reinicia o estado dos componentes
	 */
	private void resetStates() {
		for (Component component : this.components.values()) {
			component.clear();
		}
	}

	/**
	 * Repassa o erro para os componentes registrados como tratadores de erros.
	 * 
	 * @param e
	 *            O erro que ocorreu
	 */
	private void callHandlers(Exception e) {
		// TODO Auto-generated method stub
	}

	public Component getComponent(String name) {
		return this.components.get(name);
	}

}
