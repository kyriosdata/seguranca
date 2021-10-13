package br.ufsc.labsec.signature;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface PrivateInformation {

	PrivateKey getPrivateKey();
	X509Certificate getCertificate();

}
