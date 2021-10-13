package br.ufsc.labsec.signature.signer.signatureSwitch;

import br.ufsc.labsec.component.Application;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.logging.Level;

public final class SwitchHelper {

    public static String getAlias(KeyStore ks) {
        try {
            return ks.aliases().nextElement();
        } catch (KeyStoreException e) {
            Application.logger.log(Level.WARNING, e.getMessage(), e);
        }
        return null;
    }

    public static PrivateKey getPrivateKey(KeyStore ks, String alias, char[] password) {
        try {
            return (PrivateKey) ks.getKey(alias, password);
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
            Application.logger.log(Level.WARNING, e.getMessage(), e);
        }
        return null;
    }

    public static X509Certificate getCertificate(KeyStore ks, String alias) {
        try {
            return (X509Certificate) ks.getCertificate(alias);
        } catch (KeyStoreException e) {
            Application.logger.log(Level.WARNING, e.getMessage(), e);
        }
        return null;
    }

    public static boolean isXml(String policy) {
        return policy.equalsIgnoreCase("XML");
    }
}
