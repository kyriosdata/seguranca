/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes;

import org.w3c.dom.Element;

import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Representa um atributo da assinatura.
 */
public interface SignatureAttribute {

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    public String getIdentifier();

    /**
     * Valida o atributo de acordo com suas regras específicas (ver normas do
     * ETSI para cada atributo).
     * @throws SignatureAttributeException
     * @throws PbadException
     */
    public void validate() throws SignatureAttributeException, PbadException;

    /**
     * Retorna o atributo codificado
     * @return O atributo em formato de nodo XML
     * @throws SignatureAttributeException
     */
    public Element getEncoded() throws SignatureAttributeException;

    /**
     * Informa se o atributo é assinado.
     * @return Indica se o atributo é assinado
     */
    public boolean isSigned();

    /**
     * Verifica se o atributo deve ter apenas uma instância na assinatura
     * @return Indica se o atributo deve ter apenas uma instância na assinatura
     */
    public boolean isUnique();
}
