package implementation;

public class CertificateIssuer {
	private String issuer;
	private String issuerSignatureAlgorithm;
	public String getIssuer() {
		return issuer;
	}
	public String getIssuerSignatureAlgorithm() {
		return issuerSignatureAlgorithm;
	}
	public CertificateIssuer(String issuer, String issuerSignatureAlgorithm) {
		super();
		this.issuer = issuer;
		this.issuerSignatureAlgorithm = issuerSignatureAlgorithm;
	}

	
}
