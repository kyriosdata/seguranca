/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes;

import org.bouncycastle.asn1.cms.Attribute;

import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

import java.io.IOException;

/**
 * Representa um atributo da assinatura.
 */
public interface SignatureAttribute {

    /**
     * Retorna o identificador do atributo.
     * @return O identificador do atributo
     */
    public String getIdentifier();

    /**
     * Valida o atributo de acordo com suas regras específicas (ver normas do
     * ETSI para cada atributo).
     * @throws SignatureAttributeException
     * @throws PbadException
     */
    public void validate() throws SignatureAttributeException, PbadException, IOException;

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato ASN1
     * @throws SignatureAttributeException
     */
    public Attribute getEncoded() throws SignatureAttributeException;

    /**
     * Informa se o atributo é assinado
     * @return Indica se o atributo é assinado
     */
    public boolean isSigned();

    /**
     * Informa se o atributo deve ter apenas uma instância na assinatura
     * @return Indica se o atributo deve ter apenas uma instância na assinatura
     */
    public boolean isUnique();
}
