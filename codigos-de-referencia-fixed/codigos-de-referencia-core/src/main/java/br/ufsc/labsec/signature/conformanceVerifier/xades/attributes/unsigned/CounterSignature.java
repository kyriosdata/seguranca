/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned;

import br.ufsc.labsec.component.Application;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.SignatureVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.XadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.CounterSignatureInterface;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureVerifierException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

import java.util.logging.Level;

/**
 * Representa uma contra assinatura no formato XAdES.
 * 
 * Esquema do atributo CounterSignature retirado do ETSI TS 101 903:
 * 
 * {@code
 * <xsd:element name="CounterSignature" type="CounterSignatureType"/>
 * <xsd:complexType name="CounterSignatureType">
 * <xsd:sequence>
 * 	<xsd:element ref="ds:Signature"/>
 * </xsd:sequence>
 * </xsd:complexType>
 * }
 */
public class CounterSignature extends XadesSignature implements CounterSignatureInterface {

    public static final String IDENTIFIER = "CounterSignature";

    /**
     * Objeto de verificador
     */
    private SignatureVerifier signatureVerifier;

    /**
     * Constrói uma contra-assinatura levando em consideração que é uma assinatura
     * dentro de um atributo de uma assinatura.
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     */
    public CounterSignature(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        super(signatureVerifier.getSignature().getXml(),
                signatureVerifier.getSignature().getEncodedAttribute(IDENTIFIER, index),
                signatureVerifier.getSignature().getContainer());
        this.signatureVerifier = (SignatureVerifier) signatureVerifier;

    }

    /**
     * Constrói uma contra assinatura XAdES a partir da representação DOM do
     * documento XML assinado, e do elemento que representa a contra assinatura
     * no documento.
     * 
     * @param xml Representação DOM de um documento XML
     * @param signature Elemento que representa a assinatura no documento
     */
    public CounterSignature(Document xml, Element signature) {
        super(xml, signature, null);
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return CounterSignature.IDENTIFIER;
    }

    /**
     * Valida o atributo e o adiciona ao relatório da assinatura.
     * @throws SignatureAttributeException Caso a assinatura é nula.
     */
    @Override
    public void validate() throws SignatureAttributeException {
        SignatureReport sigReport = new SignatureReport();
        try {
            SignatureVerifier verifier = new SignatureVerifier(this, signatureVerifier.getXadesSignatureComponent());
            verifier.verify(sigReport);
        } catch (SignatureVerifierException e) {
            Application.logger.log(Level.WARNING, e.getMessage(), e);
        }

        signatureVerifier.getXadesSignatureComponent().getVerifier().addCounterSignatureToSignatureReport(sigReport);
    }

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato de nodo XML
     * @throws SignatureAttributeException
     */
    @Override
    public Element getEncoded() throws SignatureAttributeException {
        return null;
    }

    /**
     * Informa se o atributo é assinado.
     * @return Indica se o atributo é assinado
     */
    @Override
    public boolean isSigned() {
        return false;
    }

    /**
     * Verifica se o atributo deve ter apenas uma instância na assinatura
     * @return Indica se o atributo deve ter apenas uma instância na assinatura
     */
    @Override
    public boolean isUnique() {
        return false;
    }
}
