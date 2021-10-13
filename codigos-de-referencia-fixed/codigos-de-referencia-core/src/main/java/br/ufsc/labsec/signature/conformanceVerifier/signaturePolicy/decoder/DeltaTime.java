/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;

///**
// * DeltaTime ::= SEQUENCE {
// deltaSeconds    INTEGER,
// deltaMinutes    INTEGER,
// deltaHours      INTEGER,
// deltaDays       INTEGER }
// */
/**
 * Este elemento é usado para representar o tempo indicado pelos atributos
 * <code>cautionPeriod</code> e <code>signatureTimestampDelay</code>.
 */
public class DeltaTime {

    /**
     * Os segundos do tempo
     */
    private ASN1Integer deltaSeconds;
    /**
     * Os minutos do tempo
     */
    private ASN1Integer deltaMinutes;
    /**
     * As horas do tempo
     */
    private ASN1Integer deltaHours;
    /**
     * Os dias do tempo
     */
    private ASN1Integer deltaDays;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param deltaTime codificação ASN1 do atributo {@link DeltaTime}.
     */
    public DeltaTime(ASN1Sequence deltaTime) {

        this.deltaSeconds = (ASN1Integer) deltaTime.getObjectAt(0);
        this.deltaMinutes = (ASN1Integer) deltaTime.getObjectAt(1);
        this.deltaHours = (ASN1Integer) deltaTime.getObjectAt(2);
        this.deltaDays = (ASN1Integer) deltaTime.getObjectAt(3);
    }

    /**
     * Retorna os segundos do tempo indicado
     * @return Os segundos
     */
    public ASN1Integer getDeltaSeconds() {
        return deltaSeconds;
    }

    /**
     * Retorna os minutos do tempo indicado
     * @return Os minutos
     */
    public ASN1Integer getDeltaMinutes() {
        return deltaMinutes;
    }

    /**
     * Retorna as horas do tempo indicado
     * @return As horas
     */
    public ASN1Integer getDeltaHours() {
        return deltaHours;
    }

    /**
     * Retorna os dias do tempo indicado
     * @return Os dias
     */
    public ASN1Integer getDeltaDays() {
        return deltaDays;
    }

}
