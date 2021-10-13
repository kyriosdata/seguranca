package br.ufsc.labsec.signature.conformanceVerifier.report;

import java.util.Objects;
import java.util.logging.Level;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import br.ufsc.labsec.component.Application;

/**
 * Esta classe representa o relatório de um atributo da assinatura
 */
public class AttribReport {

	public enum HasBeenValidated {
		TRUE, FALSE, NOT_VALIDATED
    }

	/**
	 * Nome do atributo
	 */
	private String attributeName;
	/**
	 * Validade do atributo
	 */
	private HasBeenValidated isValid;
	/**
	 * Mensagem de erro
	 */
	private String errorMessage;
	/**
	 * Presença de alerta
	 */
	private boolean warning;
	/**
	 * Mensagem de alerta
	 */
	private String warningMessage;

	/**
	 * Construtor
	 */
	public AttribReport() {
		this.isValid = HasBeenValidated.TRUE;
	}

    /**
     * Atribue name ao atributo
     * @param name O nome do atributo
     */
    public void setAttribName(String name) {
        this.attributeName = name;
    }

    /**
     * Atribue a validade do atributo
     * @param error A validade do atributo
     */
    public void setError(HasBeenValidated error) {
        this.isValid = error;
    }

    /**
     * Atribue presença de erro no atributo
     * @param error Presença de erro no atributo
     */
	public void setError(boolean error) {
		this.isValid = error ? HasBeenValidated.FALSE : HasBeenValidated.TRUE;
	}

	/**
	 * Retorna a mensagem de erro
	 * @return A mensagem de erro
	 */
    public String getErrorMessage(){
    	return this.errorMessage;
    }
    
    /**
     * Atribue mensagem de erro
     * @param errorMessage A mensagem de erro
     */
    public void setErrorMessage(String errorMessage) {
    	if(errorMessage == null)
    		errorMessage = "";
        this.errorMessage = errorMessage;
    }

    /**
     * Gera elemento para mensagem de erro
     * @param document Document
     * @return {@link Element}
     */
	public Element generateErrorMessageElement(Document document) {

		Element errorMessage = document.createElement("errorMessage");

		if (this.isValid != HasBeenValidated.TRUE && this.errorMessage != null) {
			errorMessage.setTextContent(this.errorMessage);
		}

		return errorMessage;

	}
    
    /**
     * Gera elemento para alerta
     * @param document Document
     * @return {@link Element}
     */
    public Element generateAlertMessageElement(Document document) {
        Element alertMessage = document.createElement("alertMessage");
        if (this.warning)
        	alertMessage.setTextContent(this.warningMessage);
        return alertMessage;
    }

    /**
     * Gera elemento para erro
     * @param document Document
     * @return {@link Element}
     */
	public Element generateErrorElement(Document document) {

		Element error = document.createElement("error");

		if (this.isValid == HasBeenValidated.FALSE) {
			error.setTextContent("True");
		} else if (this.isValid == HasBeenValidated.NOT_VALIDATED) {
			error.setTextContent("Not validated");
		} else {
			error.setTextContent("False");
		}

		return error;

	}

    /**
     * Gera elemento para nome
     * @param document Document
     * @return {@link Element}
     */
    public Element generateNameElement(Document document) {
        Element name = document.createElement("name");
        name.setTextContent(this.attributeName);
        return name;
    }

    /**
     * Verifica se há erro no atributo
     * @return Presença de erro no atributo
     */
    public boolean hasError() {
        return this.isValid != HasBeenValidated.TRUE;
    }

    /**
     * Retorna o nome do atributo
     * @return O nome do atributo
     */
    public String getAttribName() {
        return this.attributeName;
    }

	/**
	 * Retorna a mensagem de alerta
	 * @return A mensagem de alerta
	 */
	public String getWarningMessage() {
		return this.warningMessage;
	}

	/**
	 * Atribue uma mensagem de alerta
	 * @param warningMessage A mensagem de alerta
	 */
	public void setWarningMessage(String warningMessage) {
		this.warning = true;
		this.warningMessage = warningMessage;
	}

	/**
	 * Indica se há presença de alerta
	 * @return A presença de mensagem de alerta
	 */
    public boolean hasWarning() {
    	return this.warning;
    }

	/**
	 * Retorna nome do atributo
	 * @return O nome do atributo
	 */
	@Override
    public String toString() {
    	return this.getAttribName();
    }

	/**
	 * Insere informações do atributo no log
	 * @param type Tipo do atributo (obrigatório/opcional)
	 */
	public void log(String type) {

		String err = this.errorMessage != null ? "\n" + this.errorMessage : "";
		Application.loggerInfo.log(Level.INFO,
				"Atributo " + type + ": " + this.attributeName + err);

	}

}
