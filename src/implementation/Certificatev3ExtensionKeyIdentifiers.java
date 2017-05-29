package implementation;

public class Certificatev3ExtensionKeyIdentifiers extends Certificatev3ExtensionAbstract{
	private boolean isKeyIdentifierEnabled;
	private String subjectKeyIdentifier;

	public Certificatev3ExtensionKeyIdentifiers(boolean isCritical, boolean isKeyIdentifierEnabled) {
		super(isCritical);
		this.isKeyIdentifierEnabled = isKeyIdentifierEnabled;
	}

	public Certificatev3ExtensionKeyIdentifiers(boolean isCritical, boolean isKeyIdentifierEnabled,
			String subjectKeyIdentifier) {
		super(isCritical);
		this.isKeyIdentifierEnabled = isKeyIdentifierEnabled;
		this.subjectKeyIdentifier = subjectKeyIdentifier;
	}

	public boolean isKeyIdentifierEnabled() {
		return isKeyIdentifierEnabled;
	}
	
	public String getSubjectKeyIdentifier() {
		return subjectKeyIdentifier;
	}


}
