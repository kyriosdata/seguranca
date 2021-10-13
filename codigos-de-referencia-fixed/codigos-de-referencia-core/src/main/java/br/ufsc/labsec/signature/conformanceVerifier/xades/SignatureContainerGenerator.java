/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.security.SignatureException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import br.ufsc.labsec.signature.ContentToBeSigned;
import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SignaturePolicyIdentifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.AlgorithmException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.ToBeSignedException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe gera contêineres de assinaturas no formato XAdES.
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
     * Informações do assinante
     */
	private SignerData signer;
    /**
     * Componente de assinatura XAdES
     */
	private XadesSignatureComponent component;

    /**
     * Inicia um gerador de contêineres de assinaturas XAdES
     * 
     * @param signaturePolicyIdentifier O identificador da política de
     *            assinatura
     */
    public SignatureContainerGenerator(SignaturePolicyIdentifier signaturePolicyIdentifier, XadesSignatureComponent xadesSignature) {

    	this.attributeList = new ArrayList<SignatureAttribute>();
        this.attributeSet = new HashSet<String>();
        this.contentsToBeSigned = new ArrayList<ContentToBeSigned>();
        this.signaturePolicy = xadesSignature.signaturePolicyInterface;
        
        this.addAttribute(signaturePolicyIdentifier);
        
        this.component = xadesSignature;
        
    }

    /**
     * Informa o dado que será assinado
     * 
     * @param content O dado a ser assinado
     */
    public void addContentToBeSigned(ContentToBeSigned content) {
        this.contentsToBeSigned.add(content);
    }

    /**
     * Informa qual será o assinante
     * 
     * @param signer O objeto que representa um assinante
     */
    public void setSigner(SignerData signer) {
        this.signer = signer;
    }

    /**
     * Adiciona o atributo nas listas de atributos que serão inclusos na
     * assinatura no momento de sua geração.
     * <p>
     * 
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
     * @throws SignatureAttributeException Exceção em caso de erro nos atributos da assinatura
     * @throws AlgorithmException Exceção em caso de algoritmo inválido
     * @throws EncodingException Exceção em caso de erro no documento de assinatura
     * @throws ToBeSignedException Exceção em caso de erro na URI do conteúdo a ser assinado
     * @throws PbadException Exceção em caso de modo de assinatura inválido
     */
    public SignatureContainer sign() throws SignatureAttributeException, AlgorithmException, EncodingException, ToBeSignedException, PbadException {
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
     * @throws ToBeSignedException Exceção em caso de erro na URI do conteúdo a ser assinado
     * @throws PbadException Exceção em caso de modo de assinatura inválido
     */
    public void prepareToSign() throws ToBeSignedException, PbadException {
//        List<String> mandatedSignedAttributes = this.signaturePolicy.getMandatedSignedAttributeList();
//        for (String mandatedSignedAttribute : mandatedSignedAttributes) {
//            if (!this.attributeSet.contains(mandatedSignedAttribute)) {
//                /**
//                 * Manda uma exceção e para o processo de geração
//                 */
//                try {
//                    throw new SignatureAttributeNotFoundException(SignatureAttributeNotFoundException.MISSING_MANDATED_SIGNED_ATTRIBUTE,
//                            mandatedSignedAttribute);
//                } catch (SignatureAttributeNotFoundException e) {
//                }
//            }
//        }
        this.generator = new XadesContainerGenerator(signaturePolicy, component);
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
     * Retorna quais conteúdos serão assinados.
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
