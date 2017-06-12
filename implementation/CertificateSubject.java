package implementation;

public class CertificateSubject {
	private String country; 
	private String state;
	private String locality;
	private String organization; 
	private String organizationUnit;
	private String commonName;
	private String signatureAlgorithm;
	
	public CertificateSubject(String country, String state, String locality, String organization,
			String organizationUnit, String commonName, String signatureAlgorithm) {
		super();
		this.country = country;
		this.state = state;
		this.locality = locality;
		this.organization = organization;
		this.organizationUnit = organizationUnit;
		this.commonName = commonName;
		this.signatureAlgorithm = signatureAlgorithm;
	}
	
	public String getCountry() {
		return country;
	}
	public String getState() {
		return state;
	}
	public String getLocality() {
		return locality;
	}
	public String getOrganization() {
		return organization;
	}
	public String getOrganizationUnit() {
		return organizationUnit;
	}
	public String getCommonName() {
		return commonName;
	}
	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}
}
