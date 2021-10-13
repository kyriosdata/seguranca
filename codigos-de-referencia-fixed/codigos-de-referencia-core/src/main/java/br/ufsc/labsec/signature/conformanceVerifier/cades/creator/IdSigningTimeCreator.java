package br.ufsc.labsec.signature.conformanceVerifier.cades.creator;

import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;

import br.ufsc.labsec.signature.SystemTime;
import org.bouncycastle.asn1.x509.Time;

import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesAttributeIncluder;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdSigningTime;

/**
 * Esta classe é responsável pela criação do atributo IdSigningTimeCreator
 */
public class IdSigningTimeCreator extends Creator {

	/**
	 * Construtor
	 * @param cadesAttributeIncluder Gerenciador de atributos CAdES
	 */
	public IdSigningTimeCreator(CadesAttributeIncluder cadesAttributeIncluder) {
		super(cadesAttributeIncluder);
	}

	/**
	 * Retorna o atributo
	 * @return Um objeto do atributo
	 */
	@Override
	public SignatureAttribute getAttribute() {
		Time time = new Time(new Date(SystemTime.getSystemTime()));
		IdSigningTime idSigningTime = new IdSigningTime(time);
		return idSigningTime;
	}

}
