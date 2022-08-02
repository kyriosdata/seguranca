package com.github.kyriosdata.seguranca.exemplos;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

/**
 * Exibe aliases contidas num certificado.
 */
public class Aliases {
    public static void main(String[] args) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        String certificado = System.getenv("CERTIFICADO_TESTE");
        String password = System.getenv("CERTIFICADO_SENHA");

        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(new FileInputStream(certificado), password.toCharArray());

        Enumeration<String> aliases = store.aliases();
        while (aliases.hasMoreElements()) {
            System.out.println(aliases.nextElement());
        }
    }
}
