package com.github.kyriosdata.seguranca.exemplos;

import org.demoiselle.signer.core.CertificateLoader;
import org.demoiselle.signer.core.CertificateLoaderImpl;
import org.demoiselle.signer.core.extension.ICPBrasilExtension;
import org.demoiselle.signer.core.extension.ICPBrasilExtensionType;

import java.io.File;
import java.security.cert.X509Certificate;

/**
 * Veja como produzir um arquivo (contêiner de certificados no formato PEM)
 * em https://www.baeldung.com/java-keystore-convert-to-pem-format.
 * Tal arquivo deve ser passado como argumento para o programa abaixo.
 *
 */
public class Certificado {

    final String CER

    public static void main(String[] args) throws Exception {
        // Arquivos: .cer, .crt (veja README.md em resources acerca de como gerar)
        File certificado = new File(args[0]);
        System.out.format("Arquivo %s existe? %b", args[0], certificado.exists());
        CertificateLoader cl = new CertificateLoaderImpl();
        X509Certificate x509 = cl.load(certificado);
        System.out.println(x509);
    }
}

class DetalhesCertificado {

    @ICPBrasilExtension(type=ICPBrasilExtensionType.NAME)
    private String nome;

    public String getNome() {
        return nome;
    }

    @Override
    public String toString() {
        return "DetalhesCertificado{" +
                ", nome='" + nome + '\'' +
                '}';
    }
}
