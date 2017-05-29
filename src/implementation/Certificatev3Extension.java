package implementation;

public class Certificatev3Extension {
	private Certificatev3ExtensionBasicConstraint extBasicConstraint;
	private Certificatev3ExtensionIssuerAlternativeName extIssuerAlternativeNames;
	private Certificatev3ExtensionKeyIdentifiers extKeyIdentifiers;
	public Certificatev3Extension(Certificatev3ExtensionBasicConstraint extBasicConstraint,
			Certificatev3ExtensionIssuerAlternativeName extIssuerAlternativeNames,
			Certificatev3ExtensionKeyIdentifiers extKeyIdentifiers) {

		this.extBasicConstraint = extBasicConstraint;
		this.extIssuerAlternativeNames = extIssuerAlternativeNames;
		this.extKeyIdentifiers = extKeyIdentifiers;
	}
	public Certificatev3ExtensionBasicConstraint getExtBasicConstraint() {
		return extBasicConstraint;
	}
	public Certificatev3ExtensionIssuerAlternativeName getExtIssuerAlternativeNames() {
		return extIssuerAlternativeNames;
	}
	public Certificatev3ExtensionKeyIdentifiers getExtKeyIdentifiers() {
		return extKeyIdentifiers;
	}
	
	
}
