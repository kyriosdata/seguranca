package br.ufsc.labsec.signature.repository.PKCS12IdentityService;

import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.List;

import br.ufsc.labsec.signature.RevocationInformation;

public class OCSPClient implements RevocationInformation {

    @Override
    public CRLResult getCRLFromCertificate(Certificate certificate, Time timeReference) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void addCrl(List<X509Certificate> certValuesCertificates, List<X509CRL> crlsList) {
        // TODO Auto-generated method stub
        
    }

}
