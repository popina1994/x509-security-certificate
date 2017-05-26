package implementation;

public class Certificatev3ExtensionIssuerAlternativeName extends Certificatev3ExtensionAbstract {
	
	private String[] issuerAlternativeNames;

	public Certificatev3ExtensionIssuerAlternativeName(boolean isCritical, String[] issuerAlternativeNames) {
		super(isCritical);
		this.issuerAlternativeNames = issuerAlternativeNames;
	}

	public String[] getIssuerAlternativeNames() {
		return issuerAlternativeNames;
	}
	
}
