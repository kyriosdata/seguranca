package br.ufsc.labsec.signature.repository.PKCS12IdentityService;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.RevocationInformation;
import br.ufsc.labsec.signature.SystemTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.sql.Time;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.Level;
import java.util.stream.Stream;

import static java.lang.Math.abs;

public class CRLCacheManagement implements RevocationInformation {

    private static final String crlFileHeader = "crl-";
    private static final int maximumTimeout = 3000;  // DOC-ICP-05 v5.4, item 4.9.1.4.2
    private static Set<Path> cache = new HashSet<>();
    private static Path tmpDir;

    public CRLCacheManagement(String cachePath) {
        // FIXME only works for PKCS12Repository
        tmpDir = Paths.get(cachePath);
        if (!Files.isDirectory(tmpDir)) {
            try {
                Files.createDirectories(tmpDir);
            } catch (IOException e) {
                Application.logger.log(Level.SEVERE,
                        "Não foi possível criar o diretório de cache", e.getMessage());
            }
        }

        try (Stream<Path> walk = Files.walk(tmpDir)) {
            walk.filter(Files::isRegularFile)
                    .filter(x -> x.toString().contains(crlFileHeader))
                    .forEach(cache::add);
        } catch (IOException e) {
            Application.logger.log(Level.SEVERE,
                    "Não foi possível popular a cache", e.getMessage());
        }
    }

    @Override
    public CRLResult getCRLFromCertificate(Certificate certificate, Time timeReference) {
        CRLResult result = new CRLResult();

        try {
            result.crl = getFromCache((X509Certificate) certificate);
        } catch (IOException | CRLException e) {
            Application.logger.log(Level.SEVERE,
                    "LCR não pode ser obtida da cache", e.getMessage());
        }
        result.fromWeb = false;

        if (result.crl == null || !validPeriod((X509CRL) result.crl, timeReference)) {
            try {
                result.crl = getFromWeb((X509Certificate) certificate);
            } catch (IOException | CRLException e) {
                Application.logger.log(Level.SEVERE,
                        "LCR não pode ser obtida da web", e.getMessage());
            }
            result.fromWeb = true;
        }

        if (result.crl == null || !validPeriod((X509CRL) result.crl, timeReference)) {
            return null;
        }

        return result;
    }

    private boolean validPeriod(X509CRL crl, Time ref) {
        return ref.after(crl.getThisUpdate()) && ref.before(crl.getNextUpdate());
    }

    private Path getTempFilePath(X509Certificate cert) {
        // shouldn't cause problems to return only a fraction of a hash
        String sigHash = Hex.toHexString(cert.getSignature()).substring(0, 32);;
        return tmpDir.resolve(crlFileHeader + sigHash);
    }

    private CRL getFromCache(X509Certificate certificate)
            throws IOException, CRLException {
        CRL crl = null;
        Path tmpFile = getTempFilePath(certificate);

        if (cache.contains(tmpFile)) {
            X509CRL x509CRL;
            try (InputStream is = Files.newInputStream(tmpFile)) {
                CertificateFactory cf = CertificateFactory.getInstance("X509");
                x509CRL = (X509CRL) cf.generateCRL(is);
                BasicFileAttributes attrs = Files.readAttributes(tmpFile, BasicFileAttributes.class);
                // Java's `FileTime lastAccessTime()` returns time in GMT+0 Timezone. We need to convert it to
                // System's Timezone.
                Date lastAccess = new Date(attrs.lastAccessTime().toMillis() + SystemTime.getTimeZoneDifference());
                Calendar cal = Calendar.getInstance();
                cal.add(Calendar.DATE, 7);

                // a CRL's next update value could be used to implement this,
                // but there are several signatures made in the past whose
                // certificates point to CRLs which are not updated anymore.
                // thus, a CRL file stays for one week in the cache unless
                // it's touched
                if (lastAccess.after(cal.getTime())) {
                    cache.remove(tmpFile);
                    if (tmpFile.toFile().delete()) {
                        Application.logger.log(Level.INFO,
                                "LCR antiga no caminho " + tmpFile.toAbsolutePath() + " removida");
                    }
                } else {
                    crl = x509CRL;
                }
            } catch (CertificateException e) {
                Application.logger.log(Level.SEVERE,
                        "Falha na criação de CertificateFactory", e.getMessage());
            }
        }

        return crl;
    }

    private CRL getFromWeb(X509Certificate certificate)
            throws IOException, CRLException {
        X509CRL crl = null;
        List<String> distPointUrls = getCrlDistributionPoints(certificate);

        Iterator<String> it = distPointUrls.iterator();
        while (it.hasNext() && crl == null) {
            try {
                crl = downloadCRL(it.next());
            } catch (CertificateException e) {
                Application.logger.log(Level.SEVERE,
                        "Falha na criação de CertificateFactory", e.getMessage());
            } catch (NamingException e) {
                Application.logger.log(Level.SEVERE,
                        "Falha na obtenção de CRL através de LDAP", e.getMessage());
            }
        }

        if (crl != null) {
            Path tmpFile = getTempFilePath(certificate);
            try (OutputStream os = Files.newOutputStream(tmpFile)) {
                os.write(crl.getEncoded());
            }
            cache.add(tmpFile);
        }

        return crl;
    }

    private List<String> getCrlDistributionPoints(Certificate certificate) {
        List<String> crlUrls = new ArrayList<>();
        X509Certificate cert = (X509Certificate) certificate;
        byte[] ext = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());

        if (ext == null) {
            Application.logger.log(Level.SEVERE,
                    "Extensão CRLDistributionPoints ausente no certificado");
            return crlUrls;
        }

        try {
            CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(ext));
            for (DistributionPoint dp : crlDistPoint.getDistributionPoints()) {
                DistributionPointName dpn = dp.getDistributionPoint();
                if (dpn.getType() == DistributionPointName.FULL_NAME) {
                    GeneralName[] crlNames = GeneralNames.getInstance(dpn.getName()).getNames();
                    for (GeneralName crlName : crlNames) {
                        if (crlName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            crlUrls.add(DERIA5String.getInstance(crlName.getName()).toString());
                        }
                    }
                }
            }
        } catch (IOException e) {
            Application.logger.log(Level.SEVERE,
                    "Extensão CRLDistributionPoints não pode ser construída", e.getMessage());
        }

        return crlUrls;
    }

    private X509CRL downloadCRL(String crlURL) throws IOException,
            CertificateException, CRLException, NamingException {
        if (crlURL.startsWith("http://") || crlURL.startsWith("https://")
                || crlURL.startsWith("ftp://")) {
            return downloadCRLFromWeb(crlURL);
        }

        if (crlURL.startsWith("ldap://")) {
            return downloadCRLFromLDAP(crlURL);
        }

        return null;
    }

    private X509CRL downloadCRLFromWeb(String crlURL)
            throws IOException, CertificateException, CRLException {
        CRL temp;

        URL url = new URL(crlURL);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setConnectTimeout(maximumTimeout);
        int response = connection.getResponseCode();

        // fail if not found or first redirect followed does not work
        if (response == HttpURLConnection.HTTP_NOT_FOUND) {
            return null;
        }

        if (response >= HttpURLConnection.HTTP_MULT_CHOICE
                && response <= HttpURLConnection.HTTP_SEE_OTHER) {
            String newUrl = connection.getHeaderField("Location");
            connection = (HttpURLConnection) new URL(newUrl).openConnection();
            connection.setConnectTimeout(maximumTimeout);
            response = connection.getResponseCode();
        }

        if (response != HttpURLConnection.HTTP_OK) {
            return null;
        }

        try (InputStream download = connection.getInputStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            temp = cf.generateCRL(download);
        }

        return (X509CRL) temp;
    }

    private X509CRL downloadCRLFromLDAP(String ldapURL)
            throws CertificateException, NamingException, CRLException {
        Map<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY,
                "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapURL);

        DirContext ctx = new InitialDirContext((Hashtable) env);
        Attributes avals = ctx.getAttributes("");
        Attribute aval = avals.get("certificateRevocationList;binary");
        byte[] val = (byte[]) aval.get();
        if ((val == null) || (val.length == 0)) {
            return null;
        }
        InputStream inStream = new ByteArrayInputStream(val);
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        return (X509CRL) cf.generateCRL(inStream);
    }

    @Override
    public void addCrl(List<X509Certificate> certValuesCertificates, List<X509CRL> crlsList) {
        for (X509CRL crl : crlsList) {
            for (X509Certificate certValuesCertificate : certValuesCertificates) {
                if (crl.getIssuerX500Principal().equals(
                        certValuesCertificate.getIssuerX500Principal())) {
                    cache.add(getTempFilePath(certValuesCertificate));
                }
            }
        }
    }

}
