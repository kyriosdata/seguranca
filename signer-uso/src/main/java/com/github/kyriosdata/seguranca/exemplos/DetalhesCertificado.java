package com.github.kyriosdata.seguranca.exemplos;

import org.demoiselle.signer.core.extension.ICPBrasilExtension;
import org.demoiselle.signer.core.extension.ICPBrasilExtensionType;

public class DetalhesCertificado {

    @ICPBrasilExtension(type = ICPBrasilExtensionType.NAME)
    public String name;

    @ICPBrasilExtension(type = ICPBrasilExtensionType.CPF)
    public String cpf;

    @ICPBrasilExtension(type = ICPBrasilExtensionType.EMAIL)
    public String email;

    @Override
    public String toString() {
        return "DetalhesCertificado\n" +
                "\tnome=" + name + '\n' +
                "\tcpf=" + cpf + "\n" +
                "\temail=" + email + "\n" +
                '}';
    }
}
