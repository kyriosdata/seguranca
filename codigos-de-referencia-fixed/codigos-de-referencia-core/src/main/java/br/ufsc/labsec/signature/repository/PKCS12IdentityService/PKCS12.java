package br.ufsc.labsec.signature.repository.PKCS12IdentityService;


public class PKCS12 {

    private PKCS12Repository pkcs12Repository;
    private PKCS12PrivateInformationImpl pkcsPrivateInformation;
    private PKCS12Repository component;

    public PKCS12(PKCS12Repository repository) {
        this.component = repository;
        this.pkcsPrivateInformation = new PKCS12PrivateInformationImpl(this);
    }

    public PKCS12PrivateInformationImpl getPrivateInformation() {
        return pkcsPrivateInformation;
    }


    public PKCS12Repository getRepository() {
        return this.component;
    }

}
