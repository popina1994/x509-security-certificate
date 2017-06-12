package implementation;

public class Certificatev3ExtensionKeyIdentifiers extends Certificatev3ExtensionAbstract{
	private boolean isKeyIdentifierEnabled;
	private String subjectKeyIdentifier;
	private String authorityKeyIdentifier;
	private String serialNumber;
	private String issuer;

	public Certificatev3ExtensionKeyIdentifiers(boolean isCritical, boolean isKeyIdentifierEnabled) {
		super(isCritical);
		this.isKeyIdentifierEnabled = isKeyIdentifierEnabled;
	}

	public Certificatev3ExtensionKeyIdentifiers(boolean isCritical, boolean isKeyIdentifierEnabled,
			String subjectKeyIdentifier, String authorityKeyIdentifier,
			String issuer, String serialNumber) {
		super(isCritical);
		this.isKeyIdentifierEnabled = isKeyIdentifierEnabled;
		this.subjectKeyIdentifier = subjectKeyIdentifier;
		this.authorityKeyIdentifier = authorityKeyIdentifier;
		this.issuer = issuer;
		this.serialNumber = serialNumber;
	}

	public boolean isKeyIdentifierEnabled() {
		return isKeyIdentifierEnabled;
	}
	
	public String getSubjectKeyIdentifier() {
		return subjectKeyIdentifier;
	}

	public String getAuthorityKeyIdentifier() {
		return authorityKeyIdentifier;
	}

	public String getSerialNumber() {
		return serialNumber;
	}

	public String getIssuer() {
		return issuer;
	}
	
	
	
	
}
