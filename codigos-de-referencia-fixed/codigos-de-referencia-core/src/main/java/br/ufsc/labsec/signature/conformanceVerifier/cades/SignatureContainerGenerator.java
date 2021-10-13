/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades;

import java.security.SignatureException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import br.ufsc.labsec.signature.ContentToBeSigned;
import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaEtsSigPolicyId;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe gera contêineres de assinaturas no formato CAdES.
 */
public class SignatureContainerGenerator {

    /**
     * Lista de atributos inseridos no gerador para criar uma assinatura
     */
    protected List<SignatureAttribute> attributeList;
    /**
     * Lista de conteúdos a serem assinados
     */
    protected List<ContentToBeSigned> contentsToBeSigned;
    /**
     * Informações do assinante
     */
    protected SignerData signer;
    /**
     * Conjunto de atributos da assinatura
     */
    protected Set<String> attributeSet;
    /**
     * Política de assinatura
     */
    private SignaturePolicyInterface signaturePolicy;
    /**
     * Gerador de contêiner
     */
    private ContainerGenerator generator;
    /**
     * Atributo da política de assinatura
     */
    private IdAaEtsSigPolicyId signaturePolicyIdentifier;
    /**
     * Componente de assinatura CAdES
     */
    private CadesSignatureComponent cadesSignature;

    /**
     * Inicia um gerador de contêineres de assinaturas.
     * @param signaturePolicyIdentifier O identificador da política de
     *            assinatura.
     */
    public SignatureContainerGenerator(IdAaEtsSigPolicyId signaturePolicyIdentifier, CadesSignatureComponent cadesSignature) {
        this.cadesSignature = cadesSignature;
        this.signaturePolicyIdentifier = signaturePolicyIdentifier;
        this.attributeList = new ArrayList<SignatureAttribute>();
        this.attributeSet = new HashSet<String>();
        this.addAttribute(signaturePolicyIdentifier);
        this.contentsToBeSigned = new ArrayList<ContentToBeSigned>();
        this.signaturePolicy = cadesSignature.signaturePolicyInterface;
    }

    /**
     * Informa o dado que será assinado.
     * @param content O conteúdo assinado
     */
    public void addContentToBeSigned(ContentToBeSigned content) {
        this.contentsToBeSigned.add(content);
    }

    /**
     * Informa qual será o assinante
     * @param signer O objeto que representa um assinante
     */
    public void setSigner(SignerData signer) {
        this.signer = signer;
    }

    /**
     * Adiciona os atributos nas listas de atributos que serão inclusos na
     * assinatura no momento de sua geração.
     * Para adicionar atributos assinados em uma assinatura esse método deve ser
     * utilizado.
     * 
     * @param attribute O atributo a ser adicionado
     */
    public void addAttribute(SignatureAttribute attribute) {
        this.attributeList.add(attribute);
        this.attributeSet.add(attribute.getIdentifier());
    }

    /**
     * Gera a assinatura
     * @return O contêiner que contém a assinatura gerada
     */
    public SignatureContainer sign() {
        if (this.generator == null)
            prepareToSign();
        SignatureContainer container = this.generator.generate();
        return container;
    }

    /**
     * Inicia o processo para assinar. O processo inclui: <br>
     * - Verificar se os atributos assinados obrigatórios foram setados; <br>
     * - Inicializar o {@link ContainerGenerator} de acordo com seu padrão
     * (Xades ou Cades); <br>
     * - Adicionar ao gerador os atributos já setados, adicionar o conteúdo da
     * assinatura e adicionar as informações do assinante.
     * <p>
     * 
     * <b>Obs.:</b> Este método foi criado para ser possível ter acesso as
     * refêrencias do conteúdo que será assinado antes de gerar a assinatura.
     */
    public void prepareToSign() {
        List<String> mandatedSignedAttributes = this.signaturePolicy.getMandatedSignedAttributeList();
        for (String mandatedSignedAttribute : mandatedSignedAttributes) {
            if (!this.attributeSet.contains(mandatedSignedAttribute)) {
                /**
                 * Manda uma exceção e para o processo de geração
                 */
                try {
                    throw new SignatureAttributeNotFoundException(SignatureAttributeNotFoundException.MISSING_MANDATED_SIGNED_ATTRIBUTE,
                            mandatedSignedAttribute);
                } catch (SignatureAttributeNotFoundException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        }
        this.generator = new CadesContainerGenerator(this.cadesSignature);
        try {
            this.generator.setAttributes(this.attributeList);
        } catch (SignatureAttributeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        this.generator.setContentsToBeSigned(this.contentsToBeSigned);
        this.generator.setSigner(this.signer);
    }

    /**
     * Informa quais conteúdos serão assinados.
     * @return A lista de conteúdos que serão assinados
     */
    public List<ContentToBeSigned> getContentsToBeSigned() {
        return this.contentsToBeSigned;
    }

    /**
     * Retorna o gerador de contêiner
     * @return O gerador de contêiner
     */
    public ContainerGenerator getContainerGenerator() {
        return this.generator;
    }
}
