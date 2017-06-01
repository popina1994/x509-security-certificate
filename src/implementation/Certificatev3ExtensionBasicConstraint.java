package implementation;

public class Certificatev3ExtensionBasicConstraint extends Certificatev3ExtensionAbstract{

	private String pathLength;
	private boolean isCertificateAuthority;

	public Certificatev3ExtensionBasicConstraint(boolean isCritical, String pathLength,
			boolean isCertificateAuthority) {
		super(isCritical);
		this.pathLength = pathLength;
		this.isCertificateAuthority = isCertificateAuthority;
	}

	public String getPathLength() {
		return pathLength;
	}

	public boolean isCertificateAuthority() {
		return isCertificateAuthority;
	}
}
