package com.github.kyriosdata.seguranca.exemplos;

import org.demoiselle.signer.core.CertificateLoader;
import org.demoiselle.signer.core.CertificateLoaderImpl;
import org.demoiselle.signer.core.CertificateManager;

import java.io.File;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

/**
 * Veja como produzir um arquivo (contêiner de certificados no formato PEM)
 * em https://www.baeldung.com/java-keystore-convert-to-pem-format.
 * Tal arquivo deve ser passado como argumento para o programa abaixo.
 */
public class Certificado {

    /**
     * Usa variável de ambiente 'CERTIFICADO_SIGNER' para arquivo contendo
     * certificado a ser analisado. Caso não encontrado, usa argumento e,
     * se não fornecido, usa arquivo 'keystore.cer' (resources).
     */
    public static void main(String[] args) {
        String certificadoArquivo = System.getenv("CERTIFICADO_SIGNER");
        if (certificadoArquivo == null) {
            certificadoArquivo = args.length == 1 ? args[0] : "src/main/resources/keystore.cer";
        }

        File certificado = new File(certificadoArquivo);
        System.out.format("Arquivo %s existe? %b\n",
                certificadoArquivo, certificado.exists());
        CertificateLoader cl = new CertificateLoaderImpl();
        X509Certificate x509 = cl.load(certificado);

        CertificateManager cm = new CertificateManager(x509, true);
        DetalhesCertificado dc = cm.load(DetalhesCertificado.class);
        System.out.println(dc);

        try {
            x509.checkValidity();
            System.out.println(x509.getNotAfter());
            System.out.println(x509.getIssuerX500Principal().getName());
        } catch (CertificateNotYetValidException e) {
            throw new RuntimeException(e);
        } catch (CertificateExpiredException e) {
            System.out.println("Certificado expirado" + e);
        }
    }
}

