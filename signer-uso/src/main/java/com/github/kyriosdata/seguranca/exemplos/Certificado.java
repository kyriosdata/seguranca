package com.github.kyriosdata.seguranca.exemplos;

import org.demoiselle.signer.core.CertificateLoader;
import org.demoiselle.signer.core.CertificateLoaderImpl;
import org.demoiselle.signer.core.CertificateManager;

import java.io.File;
import java.security.cert.X509Certificate;

/**
 * Veja como produzir um arquivo (contêiner de certificados no formato PEM)
 * em https://www.baeldung.com/java-keystore-convert-to-pem-format.
 * Tal arquivo deve ser passado como argumento para o programa abaixo.
 */
public class Certificado {

    final static String CER = "src/main/resources/keystore.cer";
    final static String CRT = "src/main/resources/keystore.crt";
    final static String PEM = "src/main/resources/keystore.pem";

    public static void main(String[] args) throws Exception {
        // Arquivos: .cer, .crt (veja README.md em resources acerca de como gerar)
        final String certificadoArquivo = args.length == 1 ? args[0] : CER;

        File certificado = new File(certificadoArquivo);
        System.out.format("Arquivo %s existe? %b\n",
                certificadoArquivo, certificado.exists());
        CertificateLoader cl = new CertificateLoaderImpl();
        X509Certificate x509 = cl.load(certificado);

        CertificateManager cm = new CertificateManager(x509, false);
        DetalhesCertificado dc = cm.load(DetalhesCertificado.class);
        System.out.format("Nome: %s", dc.getName());
    }
}

