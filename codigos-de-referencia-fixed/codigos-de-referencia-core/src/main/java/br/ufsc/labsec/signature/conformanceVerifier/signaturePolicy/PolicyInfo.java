package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy;

/**
 * Esta classe engloba as informações de uma política de assinatura
 */
public class PolicyInfo {

	/** Versão da política */
	private String version;
	/** O período de validade da política */
	private String[] signingPeriod;
	/** O identificador da política */
	private String policyOid;
	/** URI da politica */
	private String artifactPolicyUri;
	/** Resumo cripográfico da política */
	private String artifactPolicyDigest;
	/** Algoritmo da política */
	private String artifactPolicyMethod;
	/** Data da revogação da política, se houver */
	private String revocationDate;

	/**
	 * Construtor
	 * @param version Versão da política
	 * @param signingPeriod Período de validade da política
	 * @param policyOid Identificador da política
	 * @param artifactPolicyUri URI da politica
	 * @param artifactPolicyDigest Resumo cripográfico da política
	 * @param artifactPolicyMethod Método utilizado no cálculo de resumo
	 * @param revocationDate Data da revogação da política
	 */
	public PolicyInfo(String version, String[] signingPeriod, String policyOid, String artifactPolicyUri, String artifactPolicyDigest, String artifactPolicyMethod, String revocationDate){
		this.version = version;
		this.signingPeriod = signingPeriod;
		this.policyOid = policyOid;
		this.artifactPolicyUri = artifactPolicyUri;
		this.artifactPolicyDigest = artifactPolicyDigest;
		this.artifactPolicyMethod = artifactPolicyMethod;
		this.revocationDate = revocationDate;
		//System.out.println(policyOid);
	}

	/**
	 * Retorna o período de validade da política
	 * @return O período de validade da política
	 */
	public String[] getSigningPeriods() {
		return this.signingPeriod;
	}

	/**
	 * Retorna o identificador da política
	 * @return O identificador da política
	 */
	public String getPolicyOid(){
		return policyOid;
	}

	/**
	 * Retorna o período de validade da política
	 * @return O período de validade da política
	 */
	public String[] getSigningPeriod() {
		return signingPeriod;
	}

	/**
	 * Atribue o período de validade da política
	 * @param signingPeriod O período de validade da política
	 */
	public void setSigningPeriod(String[] signingPeriod) {
		this.signingPeriod = signingPeriod;
	}

	/**
	 * Retorna a URI da política
	 * @return A URI da política
	 */
	public String getArtifactPolicyUri() {
		return artifactPolicyUri;
	}

	/**
	 * Atribue a URI da política
	 * @param artifactPolicyUri A URI da política
	 */
	public void setArtifactPolicyUri(String artifactPolicyUri) {
		this.artifactPolicyUri = artifactPolicyUri;
	}

	/**
	 * Retorna o resumo criptográfico da política
	 * @return O resumo criptográfico da política
	 */
	public String getArtifactPolicyDigest() {
		return artifactPolicyDigest;
	}

	/**
	 * Atribue o resumo criptográfico da política
	 * @param artifactPolicyDigest O resumo criptográfico da política
	 */
	public void setArtifactPolicyDigest(String artifactPolicyDigest) {
		this.artifactPolicyDigest = artifactPolicyDigest;
	}

	/**
	 * Retorna o algoritmo da política
	 * @return O algoritmo da política
	 */
	public String getArtifactPolicyMethod() {
		return artifactPolicyMethod;
	}

	/**
	 * Atribue o algoritmo da política
	 * @param artifactPolicyMethod O algoritmo da política
	 */
	public void setArtifactPolicyMethod(String artifactPolicyMethod) {
		this.artifactPolicyMethod = artifactPolicyMethod;
	}

	/**
	 * Retorna a data de revogação da política
	 * @return A data de revogação
	 */
	public String getRevocationDate() {
		return revocationDate;
	}

	/**
	 * Atribue a data de revogação da política
	 * @param revocationDate A data de revogação
	 */
	public void setRevocationDate(String revocationDate) {
		this.revocationDate = revocationDate;
	}

	/**
	 * Atribue o identificador da política
	 * @param policyOid O identificador da política
	 */
	public void setPolicyOid(String policyOid) {
		this.policyOid = policyOid;
	}

	/**
	 * Retorna a versão da política
	 * @return A versão da política
	 */
	public String getVersion() {
		return version;
	}

	/**
	 * Atribue a versão da política
	 * @param version A versão da política
	 */
	public void setVersion(String version) {
		this.version = version;
	}
	
	
	
	

}
