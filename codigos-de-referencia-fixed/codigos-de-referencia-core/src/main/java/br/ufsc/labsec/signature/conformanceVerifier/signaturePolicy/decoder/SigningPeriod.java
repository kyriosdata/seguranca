/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import java.sql.Time;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Sequence;
import org.w3c.dom.Node;

///**
// * SigningPeriod ::= SEQUENCE {
// * notBefore GeneralizedTime,
// * notAfter GeneralizedTime OPTIONAL }
// */
///**
// * <xsd:complexType name="TimePeriodType">
// * <xsd:sequence>
// * <xsd:element name="NotBefore" type="xsd:dateTime"/>
// * <xsd:element name="NotAfter" type="xsd:dateTime" minOccurs="0"/>
// * </xsd:sequence>
// * </xsd:complexType>
// */
/**
 * Este atributo é usado pelo atributo {@link SignatureValidationPolicy}. Ele
 * especifica o intervalo de tempo em que a Política de Assinatura deve ser
 * usada.
 */
public class SigningPeriod {

    /**
     * A data de início do período de validade da política
     */
    private Date notBefore;
    /**
     * A data de fim do período de validade da política
     */
    private Date notAfter;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param signingPeriod codificação ASN1 do atributo {@link CommonRules}.
     * @throws ParseException Exceção em caso de erro no parsing da data no atributo
     */
    public SigningPeriod(ASN1Sequence signingPeriod) throws ParseException {
        this.notAfter = null;
        this.notBefore = ((ASN1GeneralizedTime) signingPeriod.getObjectAt(0)).getDate();
        if (signingPeriod.size() == 2) {
            this.notAfter = ((ASN1GeneralizedTime) signingPeriod.getObjectAt(1)).getDate();
        }
    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML.
     * @param signingPeriod elemento XML que representa o atributo
     *            {@link CommonRules}.
     * @throws ParseException Exceção em caso de erro no parsing da data no atributo
     */
    public SigningPeriod(Node signingPeriod) throws ParseException {
        this.notAfter = null;
        String contentBefore = signingPeriod.getFirstChild().getTextContent();
        DateFormat dataFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS");
        try {
            this.notBefore = dataFormat.parse(contentBefore);
        } catch (Exception e) {
            dataFormat = new SimpleDateFormat("yyyy-MM-dd");
            this.notBefore = dataFormat.parse(contentBefore);
        }
        if (signingPeriod.getChildNodes().getLength() > 1) {
            String contentAfter = signingPeriod.getLastChild().getTextContent();
            dataFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS");
            try {
                this.notAfter = dataFormat.parse(contentAfter);
            } catch (Exception e) {
                dataFormat = new SimpleDateFormat("yyyy-MM-dd");
                this.notAfter = dataFormat.parse(contentBefore);
            }
        }
    }

    /**
     * Retorna a data de início do período
     * @return A data de início do período
     */
    public Date getNotBefore() {
        return this.notBefore;
    }

    /**
     * Retorna a data de fim do período
     * @return A data de fim do período
     */
    public Date getNotAfter() {
        return this.notAfter;
    }

    /**
     * Verifica se existe o atributo <code>NotAfter</code>.
     * @return Indica se o atributo não é nulo.
     */
    public boolean hasNotAfter() {
        return this.notAfter != null;
    }
}
