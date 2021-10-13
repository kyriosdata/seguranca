package br.ufsc.labsec.signature.conformanceVerifier.xades.creator;

import java.util.GregorianCalendar;
import java.util.logging.Level;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractXadesSigner;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SigningTime;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe é responsável pela criação do atributo SigningTime
 */
public class SigningTimeCreator extends Creator {

	/**
	 * Construtor
	 * @param xadesSigner Assinador XAdES
	 */
	public SigningTimeCreator(AbstractXadesSigner xadesSigner) {
		super(xadesSigner);
	}

	/**
	 * Retorna o atributo
	 * @return Um objeto do atributo
	 * @throws SignatureAttributeException Exceção caso ocorra algum erro durante
	 * a construção do objeto
	 */
	@Override
	public SignatureAttribute getAttribute() {
		
		GregorianCalendar gregorianCalendar = new GregorianCalendar();
		DatatypeFactory datatypeFactory = null;
		SigningTime signingTime = null;
		
		try {
			
			datatypeFactory = DatatypeFactory.newInstance();
			XMLGregorianCalendar signingTimeValue = datatypeFactory.newXMLGregorianCalendar(gregorianCalendar);
			signingTime = new SigningTime(signingTimeValue);
			
		} catch (DatatypeConfigurationException datatypeConfigurationException) {
			Application.logger.log(Level.SEVERE, "Não foi possível gerar o atributo Signing Time");
		} catch (SignatureAttributeException signatureAttributeException) {
			Application.logger.log(Level.SEVERE, "Não foi possível gerar o atributo Signing Time");
		}
					
		return signingTime;
		
	}

}
