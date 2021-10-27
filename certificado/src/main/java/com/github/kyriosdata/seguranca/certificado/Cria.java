package com.github.kyriosdata.seguranca.certificado;

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.threeten.bp.DateTimeUtils;
import org.threeten.bp.Instant;
import org.threeten.bp.temporal.ChronoUnit;

/**
 * Código baseado em
 * https://pt.stackoverflow.com/questions/358172/%c3%89-poss%c3%advel-criar-um-certificado-em-formato-pfx-e-definir-um-oid-para-alguns-par%c3%a2#_=_
 */
public class Cria {

    private static JcaX509ExtensionUtils extUtils;

    static SecureRandom rand;

    static {
        Security.addProvider(new BouncyCastleProvider());
        try {
            rand = SecureRandom.getInstance("SHA1PRNG");
            extUtils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            rand = new SecureRandom();
        }
    }

    /**
     * Cria um certificado de AC (a partir do qual serão emitidos outros certificados)
     */
    public static void main(String[] args) throws Exception {
        KeyPair acKeyPair = genKeyPair(4096);

        // Detalhes em https://www.in.gov.br/en/web/dou/-/portaria-n-103-de-8-de-marco-de-2021-307484928
        // O (Organization name): ICP-Brasil
        // CN (Common Name) Nome da autoridade certificadora
        // OU (Organizational Unit)
        // C (Country)
        String acSubject = "C=BR,O=ICP-Brasil,CN=Fake CA";

        // criar AC com validade de 30 anos (365 * 30)
        X509Certificate acCert = createAcCert(acSubject, new BigInteger("1234"), 365 * 30, acKeyPair);
        saveToKeystore(acCert, acKeyPair.getPrivate(), "actest.jks", "PKCS12");
        saveToFile(acCert, "actest.cer");

        System.out.println(acCert);
    }

    static void saveToKeystore(X509Certificate certificate, PrivateKey privKey, String file, String type) throws Exception {
        char[] password = "123456".toCharArray();
        KeyStore ks = KeyStore.getInstance(type);
        ks.load(null, password);

        ks.setKeyEntry("main", privKey, password, new Certificate[]{certificate});

        OutputStream out = new FileOutputStream(file);
        ks.store(out, password);
        out.close();
    }

    static void saveToFile(X509Certificate cert, String filename) throws IOException {
        JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(filename));
        pw.writeObject(cert);
        pw.close();
    }

    static X509Certificate createAcCert(String subject, BigInteger serialNumber, int validityInDays, KeyPair keyPair) throws Exception {
        X500Name issuer = new X500Name(subject);
        // data-inicio 24 horas antes, pra evitar dessincronizacao entre maquinas, horario de verao
        Instant validityStart = Instant.now().minus(24, ChronoUnit.HOURS);
        Instant validityEnd = validityStart.plus(validityInDays, ChronoUnit.DAYS);
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serialNumber,
                // se estiver usando Java >= 8, use o java.time e troque esta linha para Date.from(validityStart), Date.from(validityEnd)
                DateTimeUtils.toDate(validityStart), DateTimeUtils.toDate(validityEnd),
                issuer, keyPair.getPublic());

        KeyUsage usage = new KeyUsage(
                KeyUsage.digitalSignature
                        | KeyUsage.keyEncipherment
                        | KeyUsage.dataEncipherment
                        | KeyUsage.keyCertSign
                        | KeyUsage.cRLSign);
        certBuilder.addExtension(Extension.keyUsage, false, usage);

        KeyPurposeId[] keyPurposeIds = {
                KeyPurposeId.id_kp_OCSPSigning,
                KeyPurposeId.id_kp_timeStamping
        };

        ExtendedKeyUsage eku = new ExtendedKeyUsage(keyPurposeIds);
        certBuilder.addExtension(Extension.extendedKeyUsage, false, eku);

        BasicConstraints bc = new BasicConstraints(true);
        certBuilder.addExtension(Extension.basicConstraints, true, bc);

        boolean isCritical = true;
        PolicyQualifierInfo pqInfo = new PolicyQualifierInfo("http://www.test.com");
        PolicyInformation policyInfo = new PolicyInformation(PolicyQualifierId.id_qt_cps, new DERSequence(pqInfo));
        CertificatePolicies policies = new CertificatePolicies(policyInfo);
        certBuilder.addExtension(Extension.certificatePolicies, isCritical, policies);

        certBuilder.addExtension(Extension.subjectKeyIdentifier, true, extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));

        certBuilder.addExtension(Extension.authorityKeyIdentifier, true, extUtils.createAuthorityKeyIdentifier(keyPair.getPublic()));

        ContentSigner signer = new JcaContentSignerBuilder("SHA512WithRSAEncryption").setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(certBuilder.build(signer));

        return cert;
    }

    static KeyPair genKeyPair(int size)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator gen =
                KeyPairGenerator.getInstance("RSA",
                        BouncyCastleProvider.PROVIDER_NAME);
        gen.initialize(size, rand);
        return gen.generateKeyPair();
    }
}
