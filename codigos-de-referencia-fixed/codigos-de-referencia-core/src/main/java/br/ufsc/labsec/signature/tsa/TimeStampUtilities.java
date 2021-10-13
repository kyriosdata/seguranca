package br.ufsc.labsec.signature.tsa;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.*;
import java.security.cert.*;
import java.util.List;
import java.util.Set;

public class TimeStampUtilities {

    private static void checkTSACert(X509Certificate certificate) throws GeneralSecurityException {

        if (certificate == null)
            throw new GeneralSecurityException("Certificado nulo encontrado durante verificação. ");

        Set<String> criticalExtensionOIDs = certificate.getCriticalExtensionOIDs();
        if (!criticalExtensionOIDs.contains(Extension.extendedKeyUsage.toString())) {
            throw new KeyStoreException("Extended KeyUsage não encontrada no certificado. ");
        }

        List<String> extendedKeyUsage = certificate.getExtendedKeyUsage();
        if (!extendedKeyUsage.contains(KeyPurposeId.id_kp_timeStamping.getId())) {
            throw new KeyStoreException("Este certificado não possui o propósito de TimeStamping. ");
        }
    }

    public static BigInteger getCertificateSerialNumber(X509Certificate certificate) throws Exception {
        checkTSACert(certificate);
        return certificate.getSerialNumber();
    }

    /**
     * Retorna os certificados da URL do TSA utilizado, para que a conexão seja feita
     * @param certificates Array com os certificados SSL a serem inseridos no KeyStore
     * @return Retorna a {@link KeyStore} com os certificados
     */
    private static KeyStore getSSLCertificatesKeyStore(X509Certificate[] certificates) {

        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null);

            for (X509Certificate certificate : certificates) {
                keyStore.setCertificateEntry(certificate.getIssuerX500Principal().getName(), certificate);
            }

            return keyStore;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Gera a conexão para a url dada
     * @param urlStr A URL para qual a conexão será feita
     * @param certificatesUrls Array com os endereços dos certificados do SSL necessários
     * @return A conexão gerada
     */
    private static URLConnection getUrlConnection(String urlStr, String[] certificatesUrls)
            throws Exception {
        URL url = new URL(urlStr);

        URLConnection urlConnection = url.openConnection();
        if (urlConnection instanceof HttpsURLConnection) {
            X509Certificate[] certificates = new X509Certificate[certificatesUrls.length];

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            for (int i = 0; i < certificatesUrls.length; i++) {
                String certificateUrl = certificatesUrls[i];
                URLConnection download = new URL(certificateUrl).openConnection();
                InputStream inputStream = download.getInputStream();
                certificates[i] = (X509Certificate) certificateFactory.generateCertificate(inputStream);
            }

            KeyStore sslCertificates = getSSLCertificatesKeyStore(certificates);
            setUrlConnectionAttributes((HttpsURLConnection) urlConnection, sslCertificates);
        }
        return urlConnection;
    }

    private static void setUrlConnectionAttributes(HttpsURLConnection connection, KeyStore sslCertificates)
            throws Exception {
        TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(sslCertificates);
        TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
        SSLContext sslContext = SSLContext.getInstance("SSL");
        sslContext.init(null, trustManagers, null);
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
        connection.setDoInput(true);
    }

    /**
     * Carrega as informações de chave da TSA de acordo com aquelas que foram configuradas.
     */
    public static KeyStore keyStore(String url, String password, String[] sslCertificatesUrls) {
        try {
            URLConnection urlConnection = getUrlConnection(url, sslCertificatesUrls);
            urlConnection.connect();
            InputStream is = urlConnection.getInputStream();

            KeyStore keyStore = KeyStore.getInstance(Constants.KEYSTORE_TYPE.toString());

            keyStore.load(is, password.toCharArray());
            return keyStore;
        } catch (Exception e) {
            return null;
        }
    }

    public enum Constants {
        KEYSTORE_TYPE ("PKCS12"),
        SHA256("SHA-256"),
        SHA256_WITH_RSA("SHA256withRSA"),
        TSA_POLICY("1.2.3"),
        ID_DATA("1.2.840.113549.1.7.1"),
        VALUE_TO_TIMESTAMP("123"); // Valor qualquer usado para testes unitários, apenas.

        private final String text;

        Constants(final String text) {
            this.text = text;
        }

        @Override
        public String toString() {
            return text;
        }
    }
}
