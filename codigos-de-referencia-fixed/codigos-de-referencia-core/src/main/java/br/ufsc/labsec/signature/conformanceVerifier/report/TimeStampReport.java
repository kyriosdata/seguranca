package br.ufsc.labsec.signature.conformanceVerifier.report;

import java.sql.Time;
import java.text.SimpleDateFormat;
import java.util.Objects;
import java.util.logging.Level;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;


/**
 * Esta classe representa o relatório de um carimbo de tempo
 */
public class TimeStampReport extends SignatureReport {

    private static final String HASH = "hash";
    private static final String FALSE = "False";
    private static final String TRUE = "True";

    /**
     * Enumeração das formas de obter o carimbo
     */
    public enum StampForm {
        SigningCertificate, Certificates, CertificatesSigningCertificate
    }

    /**
     *
     */
    private boolean presentTimeStamps;
    /**
     * Nome do carimbo de tempo
     */
    private String timeStampName;
    /**
     * ID do carimbo de tempo
     */
    private String timeStampIdentifier;
    /**
     * Horário do carimbo de tempo
     */
    private String timeStampTimeReference;

    /**
     * Atribue se carimbo está presente
     * 
     * @param timeStamps boolean
     */
    public void setPresentTimeStamps(boolean timeStamps) {
        this.presentTimeStamps = timeStamps;
    }

    /**
     * Atribue o nome ao carimbo
     * 
     * @param timeStampName O nome do carimbo
     */
    public void setTimeStampName(String timeStampName) {
        this.timeStampName = timeStampName;
    }

    /**
     * Adiciona um relatório de validação de CRLs e certificados
     * 
     * @param validationData O relatório de validação de CRLs e certificados
     */
    public void addValidation(ValidationDataReport validationData) {
        this.validation.add(validationData);
    }

    /**
     * Gera o elemento da classe
     * 
     * @param document Document
     * @return {@link Element}
     * @throws SignatureAttributeException problema ao criar o documento
     */
    public Element generate(Document document) throws SignatureAttributeException {

        Element timeStamp = document.createElement("timeStamp");

        Element timeStampIdentifier = document.createElement("timeStampIdentifier");
        timeStampIdentifier.setTextContent(this.timeStampIdentifier);
        timeStamp.appendChild(timeStampIdentifier);
        
        Element timeStampName = document.createElement("timeStampName");
        timeStampName.setTextContent(this.timeStampName);
        timeStamp.appendChild(timeStampName);

        Element timeReference = document.createElement("timeStampTimeReference");
        timeReference.setTextContent(this.timeStampTimeReference);
        timeStamp.appendChild(timeReference);
        
        Element certPathElement = document.createElement("certPathValid");
        if (this.certPathValidity != null) {
            certPathElement.setTextContent(this.certPathValidity.toString());
        } else {
            certPathElement.setTextContent("null");
        }
        timeStamp.appendChild(certPathElement);

        if (this.certPathValidity != CertValidity.Valid) {
            Element certPathMessageElement = document.createElement("certPathMessage");
            certPathMessageElement.setTextContent(this.certPathMessage);
            timeStamp.appendChild(certPathMessageElement);
        }

        setTimeStampValidationData(timeStamp, document);

        Element attributes = document.createElement("attributes");
        timeStamp.appendChild(attributes);
        setRequiredAttrib(timeStamp, document, attributes);
        setOptionalAttrib(timeStamp, document, attributes);

        setIntegrityAndSchemaElements(timeStamp, document);

        return timeStamp;
    }

    /**
     * Atribue nodos ValidationData ao elemento timeStamp
     * 
     * @param timeStamp Element
     * @param document Document
     */
    private void setTimeStampValidationData(Element timeStamp, Document document) {

        for (ValidationDataReport certReport : this.validation) {
            Element cert = certReport.generateCertificateElement(document);
            if (cert != null) {
                for (ValidationDataReport lcrReport : this.validation) {
                    String issuerName = lcrReport.getCrlIssuerName();
                    if (issuerName != null) {
                        Boolean equalNames = issuerName.replaceAll("\\s", "").equals(certReport.getCertificateSubjectName().replaceAll("\\s", ""));
                        if (equalNames) {
                            Element crl = lcrReport.generateCrlElement(document);
                            if (crl != null) {
                                cert.appendChild(crl);
                                break;
                            }
                        }
                    }
                }
                timeStamp.appendChild(cert);
            }
        }

//        for (ValidationDataReport ocspReport : this.validation) {
//            timeStamp.appendChild(ocspReport.generateOcspElement(document));
//        }
    }

    /**
     * Atribuir nodo de atributos obrigatórios
     * 
     * @param timeStamp Element
     * @param document Document
     * @param attributes Element
     */
    private void setRequiredAttrib(Element timeStamp, Document document, Element attributes) {

        Element requiredAttributes = document.createElement("requiredAttributes");
        attributes.appendChild(requiredAttributes);

        for (AttribReport attrib : this.requiredAttrib) {
            Element requiredAttribute = document.createElement("requiredAttribute");
            requiredAttribute.appendChild(attrib.generateNameElement(document));
            requiredAttribute.appendChild(attrib.generateErrorElement(document));
            if (attrib.hasError()) {
                requiredAttribute.appendChild(attrib.generateErrorMessageElement(document));
            }
            if(attrib.hasWarning())
            	requiredAttribute.appendChild(attrib.generateAlertMessageElement(document));
            requiredAttributes.appendChild(requiredAttribute);
        }
    }

    /**
     * Atribuir nodo de atributos opcionais
     * 
     * @param timeStamp Element
     * @param document Document
     * @param attributes Element
     */
    private void setOptionalAttrib(Element timeStamp, Document document, Element attributes) {

        Element optionalAttributes = document.createElement("optionalAttributes");
        attributes.appendChild(optionalAttributes);

        for (AttribReport attrib : this.optionalAttrib) {
            Element optionalAttribute = document.createElement("optionalAttribute");
            optionalAttribute.appendChild(attrib.generateNameElement(document));
            optionalAttribute.appendChild(attrib.generateErrorElement(document));
            if(attrib.hasError())
            	optionalAttribute.appendChild(attrib.generateErrorMessageElement(document));
            optionalAttributes.appendChild(optionalAttribute);
        }

    }

    /**
     * Atribuir nodos de integridade e esquema ao elemento timeStamp
     * 
     * @param timeStamp Element
     * @param document Document
     */
    private void setIntegrityAndSchemaElements(Element timeStamp, Document document) {

        Element integrity = document.createElement("integrity");
        timeStamp.appendChild(integrity);

        Element schema = document.createElement("schema");
        integrity.appendChild(schema);
        schema.setTextContent(this.schema.toString());

        setReferencesAndXmlHashElements(integrity, document);
        generateAttributeValidElement(timeStamp, document);
    }

    /**
     * Atribuir nodos de referencia e xmlHash ao elemento timeStamp
     * 
     * @param integrity Element
     * @param document Document
     */
    private void setReferencesAndXmlHashElements(Element integrity, Document document) {

        Element references = document.getDocumentElement(); // em branco
        if (this.references != null) {
            references = document.createElement("references");
            integrity.appendChild(references);
        }

        for (Boolean referenceValue : this.references) {
            Element reference = document.createElement("reference");
            references.appendChild(reference);

            Element xmlHash = document.createElement(HASH);
            reference.appendChild(xmlHash);
            if (referenceValue)
                xmlHash.setTextContent(TRUE);
            else
                xmlHash.setTextContent(FALSE);
        }

        setHashAndCipherElements(integrity, document);
    }

    /**
     * Atribuir nodo de atributos obrigatórios válidos ao elemento timeStamp
     */
    private void generateAttributeValidElement(Element timeStamp, Document document) {
        Element attributeValid = document.createElement("attributeValid");
        timeStamp.appendChild(attributeValid);
        if (this.hasAttributeExceptions)
            attributeValid.setTextContent(FALSE);
        else
            attributeValid.setTextContent(TRUE);
    }

    /**
     * Atribuir nodos de hash e cifrador ao elemento timeStamp
     * 
     * @param integrity Element
     * @param document Document
     */
    private void setHashAndCipherElements(Element integrity, Document document) {

        Element hash = document.createElement(HASH);
        integrity.appendChild(hash);
        if (this.hash)
            hash.setTextContent(TRUE);
        else
            hash.setTextContent(FALSE);

        Element asymmetricCipher = document.createElement("asymmetricCipher");
        integrity.appendChild(asymmetricCipher);
        if (this.asymmetricCipher)
            asymmetricCipher.setTextContent(TRUE);
        else
            asymmetricCipher.setTextContent(FALSE);

    }

    /**
     * Retorna o ID do carimbo de tempo
     * @return O ID do carimbo de tempo
     */
	public String getTimeStampIdentifier() {
		return timeStampIdentifier;
	}

    /**
     * Atribue o ID ao carimbo de tempo
     * @param timeStampIdentifier ID do carimbo de tempo
     */
	public void setTimeStampIdentifier(String timeStampIdentifier) {
		this.timeStampIdentifier = timeStampIdentifier;
	}

    /**
     * Insere informações do carimbo de tempo no log
     */
	public void log() {

		String tsSch = isSchema() ? "" : "não ";
		Application.loggerInfo.log(Level.INFO, "Assinatura do carimbo de tempo " + tsSch
				+ "está de acordo com o schema. " + Objects.toString(this.getSchemaMessage(), ""));

		String tsPath = (this.certPathValidity == CertValidity.Valid) ? "" : "in";
		Application.loggerInfo.log(Level.INFO, "Caminho de certificação do carimbo de tempo "
				+ tsPath + "válido. " + Objects.toString(this.certPathMessage, ""));

		String tsInt = this.hash ? "" : "in";
		Application.loggerInfo.log(Level.INFO,
				"Resumo criptográfico do carimbo de tempo " + tsInt + "válido. ");

		String tsVal = this.isValid() ? "" : "in";
		Application.loggerInfo.log(Level.INFO,
				"Assinatura do carimbo de tempo " + tsVal + "válida.");

		for (AttribReport ar : this.requiredAttrib) {
			ar.log("obrigatório do carimbo do tempo");
		}

		for (AttribReport ar : this.optionalAttrib) {
			ar.log("opcional do carimbo do tempo");
		}

	}

    /**
     * Retorna o horário do carimbo
     * @return O horário do carimbo de tempo
     */
	public String getTimeReference() {
		return timeStampTimeReference;
	}

    /**
     * Atribue o horário do carimbo de tempo
     * @param timeStampTimeReference O horário do carimbo de tempo
     */
	public void setTimeReference(Time timeStampTimeReference) {
		SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss z");
		this.timeStampTimeReference = dateFormat.format(timeStampTimeReference);
	}

}
