package com.github.kyriosdata.seguranca.exemplos;

import org.demoiselle.signer.core.CertificateManager;
import org.demoiselle.signer.core.extension.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.List;

/**
 * Veja como produzir um arquivo (contêiner de certificados no formato PEM)
 * em https://www.baeldung.com/java-keystore-convert-to-pem-format.
 * Tal arquivo deve ser passado como argumento para o programa abaixo.
 */
public class Certificado {

    public static void main(String[] args) throws Exception {
        File certificado = new File(args[0]);
        FileInputStream fis = new FileInputStream(certificado);
        System.out.println("Arquivo existe: " + certificado.exists());
        BasicCertificate cm = new BasicCertificate(fis);
        System.out.println(cm.toString());
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
