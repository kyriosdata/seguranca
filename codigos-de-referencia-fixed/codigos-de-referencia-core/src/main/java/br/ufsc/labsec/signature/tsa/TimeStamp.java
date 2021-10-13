package br.ufsc.labsec.signature.tsa;

import br.ufsc.labsec.component.Component;

import br.ufsc.labsec.signature.PrivateInformation;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * Classe que representa um carimbo de tempo
 */
public abstract class TimeStamp {

	/**
	 * Retorna um carimbo de tempo pro conteúdo dado
	 * @param digest Os bytes do conteúdo que receberá um carimbo de tempo
	 * @return O carimbo de tempo pro conteúdo dado
	 */
	public abstract byte[] getTimeStamp(byte[] digest);

	protected Component component;

	public TimeStamp(TimeStampComponent timeStampComponent) {
		this.component = timeStampComponent;
	}

	protected abstract X509Certificate getCertificate();

	/**
	 * Gera uma requisição de carimbo de tempo pro conteúdo dado
	 * @param toBeTimeStamped bytes do conteúdo que receberá um carimbo de tempo
	 * @return A requisição de carimbo de tempo pro conteúdo dado
	 */
	public TimeStampRequest request(byte[] toBeTimeStamped)  {
        TimeStampRequestGenerator requestGenerator = new TimeStampRequestGenerator();

        requestGenerator.setCertReq(true);

		String algorithm = this.component.getApplication().getComponentParam(this.component, "algorithmOid");
		ASN1ObjectIdentifier digestAlg = new ASN1ObjectIdentifier(algorithm);

        BigInteger nonce = null;
        try {
            nonce = TimeStampUtilities.getCertificateSerialNumber(this.getCertificate());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return requestGenerator.generate(digestAlg, toBeTimeStamped, nonce);
	}
}
