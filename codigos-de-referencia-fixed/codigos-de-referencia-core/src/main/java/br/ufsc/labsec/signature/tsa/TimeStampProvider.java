package br.ufsc.labsec.signature.tsa;

import br.ufsc.labsec.component.Application;

import br.ufsc.labsec.signature.SimplePrivateInformation;
import br.ufsc.labsec.signature.PrivateInformation;
import br.ufsc.labsec.signature.signer.signatureSwitch.SwitchHelper;
import org.bouncycastle.tsp.*;

import java.math.BigInteger;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;
import java.util.logging.Level;

/**
 * Esta classe é responsável por se conectar localmente ao TSA e retornar um carimbo de tempo.
 * É utilizada em testes do Assinador.
 */
public class TimeStampProvider extends TimeStamp {

    private static final String KEYSTORE_URL = "http://pbad.labsec.ufsc.br/files/icp/rsa/TIMESTAMP.p12";
    private static final String KEYSTORE_PASSWORD = "1234";
    private static final String ALIAS = "TIMESTAMP";

    private PrivateInformation privateInformation;

    public TimeStampProvider(TimeStampComponent timeStampComponent) {
        super(timeStampComponent);
        String parameter;
        try {
            parameter = this.component.getApplication().getComponentParam(this.component, "tsaSSLCertificates");
        } catch (Exception e) {
            parameter = "";
        }
        // Adicionar uma "," no final evita a inserção de String com comprimento zero no array após o "split".
        String[] sslUrls = (parameter + ",").split(",");
        KeyStore keyStore = TimeStampUtilities.keyStore(KEYSTORE_URL, KEYSTORE_PASSWORD, sslUrls);
        if (keyStore != null) {
            PrivateKey privateKey = SwitchHelper.getPrivateKey(keyStore, ALIAS, KEYSTORE_PASSWORD.toCharArray());
            Certificate certificate = SwitchHelper.getCertificate(keyStore, ALIAS);
            this.privateInformation = new SimplePrivateInformation(certificate, privateKey);
        }
    }

    /**
     * @return uma TimeStampResponse para uma TimeStampRequest.
     * @apiNote calcula-se o nonce a partir do código serial do certificado.
     * @throws Exception se criar o TimeStampTokenGenerator não for possível.
     */
    public TimeStampResponse respond(TimeStampRequest tsq)
            throws Exception {

        Date now = new Date();
        TokenHandler tokenHandler = new TokenHandler(tsq, now, this.privateInformation);
        TimeStampTokenGenerator tokenGenerator = tokenHandler.createTokenGenerator();

        TimeStampResponseGenerator respGen = new TimeStampResponseGenerator(
                tokenGenerator, TSPAlgorithms.ALLOWED);

        /* Escolheu-se fazer uso de 256 bits para o nonce visto que é seguro assumir
        que um usuário nunca conseguiria obter o mesmo número mais de uma vez nesta
        condição, considerando que 0 <= nonce <= 2^256 - 1 por causa do Random utilizado.*/
        BigInteger nonce = new BigInteger(256, new Random());
        return respGen.generate(tsq, nonce, now);
    }

    /**
     * Retorna um carimbo de tempo pro conteúdo dado
     * @param digest Os bytes do conteúdo que receberá um carimbo de tempo
     * @return O carimbo de tempo pro conteúdo dado
     */
    @Override
    public byte[] getTimeStamp(byte[] digest) {
        try {
            TimeStampRequest timeStampRequest = request(digest);
            TimeStampResponse timeStampResponse = respond(timeStampRequest);
            return timeStampResponse.getEncoded();
        } catch (Exception e) {
            Application.logger.log(Level.SEVERE, "Não foi possível criar o carimbo de tempo. ");
        }
        return new byte[0];
    }

    @Override
    protected X509Certificate getCertificate() {
        return this.privateInformation.getCertificate();
    }
}
