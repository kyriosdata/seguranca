package br.ufsc.labsec.signature.tsa;

import br.ufsc.labsec.signature.PrivateInformation;
import br.ufsc.labsec.signature.tsa.TimeStampUtilities.Constants;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

import java.security.GeneralSecurityException;
import java.security.cert.CertificateEncodingException;
import java.util.Collections;
import java.util.Date;
import java.util.Hashtable;

public class TokenHandler {

    private final TimeStampRequest requestQuery;
    private final Date now;
    private PrivateInformation privateInformation;

    public TokenHandler(TimeStampRequest tsq, Date date, PrivateInformation privateInformation) {
        this.requestQuery = tsq;
        this.now = date;
        this.privateInformation = privateInformation;
    }

    /**
     * Combina signer info builder, signer info generator e um digest calculator para
     * criar o gerador do token de carimbo de tempo.
     *
     * Não faz-se a criação manual do TimeStampToken visto que o objeto de TimeStampResponse
     * precisa do gerador do token, apenas.
     *
     * @return um TimeStampTokenGenerator para gerar uma TimeStampResponse.
     *
     * @throws Exception de múltiplos tipos. Os principais são de GeneralSecurityException, no caso
     *                   de um Date ou TimeStampRequest nulo ser passado na inicialização do TokenHandler.
     */
    public TimeStampTokenGenerator createTokenGenerator()
            throws Exception {

        JcaSignerInfoGeneratorBuilder signBuilder = signerBuilder();
        setAttributeGenerator(signBuilder);

        SignerInfoGenerator signerInfoGen = signerInfoGenerator();

        DigestCalculator digestCalculator = calculateDigest();

        TimeStampTokenGenerator tokenGenerator =  new TimeStampTokenGenerator(signerInfoGen, digestCalculator, new ASN1ObjectIdentifier(
                TimeStampUtilities.Constants.TSA_POLICY.toString()));

        JcaCertStore store = new JcaCertStore(Collections.singleton(privateInformation.getCertificate()));
        tokenGenerator.addCertificates(store);
        return tokenGenerator;
    }

    private JcaSignerInfoGeneratorBuilder signerBuilder() throws OperatorCreationException {
        return new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().build());
    }

    /**
     * @return um vetor ASN1, criado a partir de uma TimeStampRequest e Date.
     *
     * @throws GeneralSecurityException se não for encontrada TimeStampRequest ou Date.
     */
    private ASN1EncodableVector signedAttributes() throws GeneralSecurityException {

        if (this.now == null)
            throw new GeneralSecurityException("Atributo de data não inicializado. ");

        if (this.requestQuery == null)
            throw new GeneralSecurityException("TimeStampRequest nula encontrada. ");

        ASN1EncodableVector signedAttributes = new ASN1EncodableVector();

        signedAttributes.add(new Attribute(CMSAttributes.contentType,
                new DERSet(new ASN1ObjectIdentifier(Constants.ID_DATA.toString()))));

        signedAttributes.add(new Attribute(CMSAttributes.messageDigest,
                new DERSet(new DEROctetString(this.requestQuery.getMessageImprintDigest()))));

        signedAttributes.add(new Attribute(CMSAttributes.signingTime,
                new DERSet(new DERUTCTime(this.now))));

        return signedAttributes;
    }

    private AttributeTable attributeTable()  {
        AttributeTable signedAttributesTable = null;

        try {
            signedAttributesTable = new AttributeTable(signedAttributes());
        } catch (GeneralSecurityException e) {
            System.err.println("Não conseguiu-se TimeStampRequest ou Date da tabela de atributos. ");
            e.printStackTrace();
        }

        assert signedAttributesTable != null: "Atributo nulo de assinatura encontrado. ";

        signedAttributesTable.toASN1EncodableVector();  // TODO verificar necessidade.
        return signedAttributesTable;
    }

    /**
     * Procura por atributos assinados e não-assinados e prepara o signBuilder de acordo com estes.
     * Para atributos, não-assinados, uma hash table é suficiente, mas, para os assinados, é
     * necessário que se tenha uma AttributeTable criada a partir de um ASN1 para atributos assinados.
     *
     * @param signBuilder como um dos objetos a serem chamados no escopo interno de {@link #createTokenGenerator}.
     */
    private void setAttributeGenerator(JcaSignerInfoGeneratorBuilder signBuilder) {
        DefaultSignedAttributeTableGenerator attrGenerator = new DefaultSignedAttributeTableGenerator(attributeTable());

        signBuilder.setSignedAttributeGenerator(attrGenerator);
        signBuilder.setUnsignedAttributeGenerator(new SimpleAttributeTableGenerator(
                new AttributeTable(
                        new Hashtable<String, String>())));
    }

    /**
     * @return informação de geração de assinatura usando SHA256 com RSA.,
     */
    private SignerInfoGenerator signerInfoGenerator() {
        SignerInfoGenerator signerInfoGen = null;

        try {
            JcaContentSignerBuilder contentSignerBuilder =
                    new JcaContentSignerBuilder(Constants.SHA256_WITH_RSA.toString());
            ContentSigner contentSigner = contentSignerBuilder.build(privateInformation.getPrivateKey());
            signerInfoGen = signerBuilder().build(contentSigner, privateInformation.getCertificate());
        } catch (OperatorCreationException | CertificateEncodingException e) {
            e.printStackTrace();
        }

        return signerInfoGen;
    }

    /**
     * @return um DigestCalculator com SHA256.
     * @throws OperatorCreationException se não puder produzir DigestCalculatorProvider,
     *         se nenhum provider for encontrado, ou se não encontrar o algoritmo desejado.
     */
    private DigestCalculator calculateDigest () throws OperatorCreationException {
        DigestCalculatorProvider build = new JcaDigestCalculatorProviderBuilder().build();
        DigestAlgorithmIdentifierFinder digestAlgorithmIdentifierFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier sha256 = digestAlgorithmIdentifierFinder.find(TimeStampUtilities.Constants.SHA256.toString());
        return build.get(sha256);
    }
}
