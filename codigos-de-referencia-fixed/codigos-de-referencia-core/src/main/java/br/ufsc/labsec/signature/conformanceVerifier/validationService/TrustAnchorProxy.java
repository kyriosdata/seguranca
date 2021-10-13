package br.ufsc.labsec.signature.conformanceVerifier.validationService;

import br.ufsc.labsec.component.Application;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.*;
import java.util.logging.Level;
import java.util.stream.Stream;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Hex;

/**
 * Esta classe representa um conjunto de âncoras de confiança
 */
public class TrustAnchorProxy implements TrustAnchorInterface {

    /*
     * Cria o diretório de cache das âncoras de confiança, somente caso o diretório ainda não exista.
     */
    public void createTrustAnchorDirectory() {
        String trustAnchorsDir = this.getTrustAnchorComponent().getApplication().getComponentParam(
                this.trustAnchorComponent, "trustAnchorsDirectory");
        Path trustAnchorPath = Paths.get(trustAnchorsDir);
        try {
            if (!Files.isDirectory(trustAnchorPath))
                Files.createDirectories(trustAnchorPath);
        } catch (IOException e) {
            /*
             * Pela necessidade de adquirir o endereço do diretório no componente, a função não pode ser
             * invocada por um bloco estático, podendo haver uma concorrência na criação do diretório.
             * Isso não parece causar um problema no funcionamento, porém, deve ser devidamente
             * identificado a falha por tentar criar um diretório já existente no log.
             */
            if (e instanceof FileAlreadyExistsException) {
                Application.logger.log(Level.SEVERE,
                        "Tentativa de criar diretório " + trustAnchorsDir + " de cache já existente", e.getMessage());
            } else {
                Application.logger.log(Level.SEVERE,
                        "Não foi possível criar o diretório " + trustAnchorsDir + " de cache", e.getMessage());
            }
        }
    }

    /**
     * Conjunto de âncoras de confiança
     */
    private Set<TrustAnchor> trustAnchor;

    /**
     * Componente de âncoras de confiança
     */
    private TrustAnchorComponent trustAnchorComponent;

    /**
     * Construtor
     * @param trustAnchorComponent Componente de âncoras de confiança
     */
    public TrustAnchorProxy(TrustAnchorComponent trustAnchorComponent) {
        this.trustAnchorComponent = trustAnchorComponent;
        this.createTrustAnchorDirectory();
    }

    /**
     * Retorn o conjunto de âncoras de confiança
     * @return O conjunto de âncoras de confiança
     */
    public Set<TrustAnchor> getTrustAnchorSet() {
        if (trustAnchor != null) return trustAnchor;

        trustAnchor = this.createTrustAnchorSet();
        return trustAnchor;
    }

    /**
     * Retorna o componente de âncoras de confiança
     * @return O componente de âncoras de confiança
     */
    public TrustAnchorComponent getTrustAnchorComponent() {
        return this.trustAnchorComponent;
    }

    /**
     * Realiza o download do arquivo através da URL dada
     * @param url A URL que será utilizada para o download
     * @return O InputStream que foi recebido da URL
     * @throws IOException Exceção em caso de erro na conexão
     */
    private InputStream getInputStreamFromURL(URL url) throws IOException {
        InputStream fileData = null;
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setConnectTimeout(1000);
        int response = connection.getResponseCode();

		if (response == HttpURLConnection.HTTP_NOT_FOUND) {
			Application.logger.log(Level.SEVERE, "A âncora de confiança não foi encontrada no endereço " + url.getPath());
			return null;
		}
		if (response >= HttpURLConnection.HTTP_MULT_CHOICE && response <= HttpURLConnection.HTTP_SEE_OTHER) {
			String newUrl = connection.getHeaderField("Location");
			connection = (HttpURLConnection) new URL(newUrl).openConnection();
			connection.setConnectTimeout(1000);
			response = connection.getResponseCode();
		}
		if (response != HttpURLConnection.HTTP_OK) {
			Application.logger.log(Level.SEVERE, "Não foi possível realizar uma conexão com sucesso em " + url.getPath()
					+ ". Código retornado na conexão: " + response);
			return null;
		}

        try {
            fileData = connection.getInputStream();
        } catch (IOException e) {
			Application.logger.log(Level.SEVERE, "Não foi possível realizar o download da âncora de confiança em " + url.getPath());
        }

        return fileData;
    }

    /**
     * Gera uma lista de {@link InputStream} das âncoras através dos arquivos presentes
     * nos diretórios determinados e dos arquivos buscados nas URLs dadas
     * @return Lista de {@link InputStream} que são os conteúdos das âncoras
     * de confiança
     */
    private List<InputStream> createTrustAnchorStreams() {
        List<InputStream> anchorStreamList = new ArrayList<InputStream>();
		String directory = this.getTrustAnchorComponent().getApplication().getComponentParam(
				this.trustAnchorComponent, "trustAnchorsDirectory");

        // Search directory
        Set<Path> anchors = new HashSet<>();
		try {
			Stream<Path> walk = Files.walk(Paths.get(directory));
			walk.filter(Files::isRegularFile)
					.forEach(anchors::add);
		} catch (IOException e) {
			Application.logger.log(Level.SEVERE, "Não foi possível ler o diretório " + directory,
					e.getMessage());
		}

        for (Path anchor : anchors) {
            try {
                InputStream is = Files.newInputStream(anchor);
                if (is == null) {
                    is = new FileInputStream(new File(anchor.toAbsolutePath().toString()));
                }
                anchorStreamList.add(is);
            } catch (IOException e) {
				Application.logger.log(Level.SEVERE, "Não foi possível ler o arquivo " + anchor.toString(),
						e.getMessage());
            }
        }

        // Download
        String trustAnchorsURLs = this.getTrustAnchorComponent().getApplication().getComponentParam(
                this.trustAnchorComponent, "trustAnchorsURLs");
        trustAnchorsURLs = trustAnchorsURLs.replaceAll("\n", ""); // remove '\n'
        String[] urls = trustAnchorsURLs.split(",");
        URL trustAnchorURL;
        for (String url : urls) {
            try {
                trustAnchorURL = new URL(url.trim());
                int lastIdx = trustAnchorURL.getPath().lastIndexOf("/");

                MessageDigest digest = MessageDigest.getInstance("SHA256");
                digest.update(trustAnchorURL.toString().getBytes());
                String hash = Hex.toHexString(digest.digest());
                Path anchorNamePath = Paths.get(directory + hash + ".crt");
                if (!anchors.contains(anchorNamePath)) {
                    InputStream is = this.getInputStreamFromURL(trustAnchorURL);
                    if (is == null) {
                        is = new FileInputStream(new File(hash + ".crt"));
                    }
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    Iterator iterator = cf.generateCertificates(is).iterator();
                    int i = 0;
                    while (iterator.hasNext())
                    {
                        Certificate c = (Certificate) iterator.next();
                        byte[] certificateBytes = c.getEncoded();
                        anchorStreamList.add(new ByteArrayInputStream(certificateBytes));
                        if (i == 0) {
                            FileUtils.writeByteArrayToFile(new File(anchorNamePath.toString()), certificateBytes);
                        } else {
                            String filePath = anchorNamePath.toString();
                            int index = filePath.lastIndexOf("/");
                            filePath = filePath.substring(0, index+1) + i +  filePath.substring(index+1);
                            FileUtils.writeByteArrayToFile(new File(filePath), certificateBytes);
                        }
                        i++;
                    }
                }
            } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
				Application.logger.log(Level.SEVERE, "Não foi possível finalizar o download da âncora de confiança em  " + url,
						e.getMessage());
            }
        }

        if (anchorStreamList.isEmpty()) {
            Application.logger.log(Level.SEVERE, "Não foi possível encontrar Âncoras de Confiança.",
                    new FileNotFoundException());
        }

        return anchorStreamList;
    }

    /**
     * Gera o conjunto de âncoras de confiança
     * @return O conjunto de âncoras de confiança
     */
    private Set<TrustAnchor> createTrustAnchorSet() {
        List<InputStream> anchors = this.createTrustAnchorStreams();
        Set<TrustAnchor> trustAnchors = new HashSet<>();

        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            boolean atLeastOne = false;

            for (InputStream anchorStream : anchors) {
                X509Certificate anchor = null;
                try {
                    anchor = (X509Certificate) factory.generateCertificate(anchorStream);
                    atLeastOne = true;
                    trustAnchors.add(new TrustAnchor(anchor, null));
                } catch (CertificateException e) {
                }
            }

            if (!atLeastOne) {
                throw new CertificateException();
            }
        } catch (CertificateException e) {
            Application.logger.log(Level.SEVERE,
                    "Não foi possível decodificar o certificado da Âncora de Confiança.", e);
        }

        return trustAnchors;
    }

}
