package br.ufsc.labsec.signature.signer.suite;

import java.util.HashMap;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

public final class SingletonSuiteMapper {

    public static final String SHA256 = NISTObjectIdentifiers.id_sha256.getId();
    public static final String SHA256withRSA = PKCSObjectIdentifiers.sha256WithRSAEncryption.getId();
    public static final String SHA256withECDSA = X9ObjectIdentifiers.ecdsa_with_SHA256.getId();
    public static final String SHA512withRSA = PKCSObjectIdentifiers.sha512WithRSAEncryption.getId();
    public static final String SHA512withECDSA = X9ObjectIdentifiers.ecdsa_with_SHA512.getId();
    public static final String Ed25519 = EdECObjectIdentifiers.id_Ed25519.getId();
    public static final String Ed448 = EdECObjectIdentifiers.id_Ed448.getId();

    private static SingletonSuiteMapper INSTANCE;
    private static String DEFAULT_SIGNATURE_SUITE = SHA256withRSA;

    public HashMap<String, String> signatureAlgorithms = new HashMap<>();

    private void loadAvailableSuites() {
        signatureAlgorithms.put(SHA256, "http://www.w3.org/2001/04/xmlenc#sha256");
        signatureAlgorithms.put(SHA256withRSA, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        signatureAlgorithms.put(SHA256withECDSA, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
        signatureAlgorithms.put(SHA512withRSA, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
        signatureAlgorithms.put(SHA512withECDSA, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512");
        signatureAlgorithms.put(Ed25519, null);
        signatureAlgorithms.put(Ed448, null);
    }

    private SingletonSuiteMapper() {}

    public static SingletonSuiteMapper getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new SingletonSuiteMapper();
        }
        INSTANCE.loadAvailableSuites();
        return INSTANCE;
    }

    public static String getDefaultSignatureSuite() {
        return DEFAULT_SIGNATURE_SUITE;
    }
}
