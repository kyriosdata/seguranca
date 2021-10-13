package br.ufsc.labsec.component;

/**
 * Esta classe representa um componente genérico
 */
public class Components {

	/**
	 * @param args
	 *            Argumentos da aplicação.
	 */
	public static void run(String[] args) {

		Application app;
		if (args.length < 1) {
			app = new Application();
		} else {
			app = new Application(args);
		}
		if (!app.setup()) {
			System.err.println("Cannot complete the component configuration correctly.");
		}
	}

}
