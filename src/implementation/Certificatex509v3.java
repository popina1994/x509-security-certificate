package implementation;

public class Certificatex509v3 {
	private int version;
	private CertificateSubject certificateSubject;
	private String serialNumber;
	private CertificateValidity certificateValidity;
	private CertificatePublicKey certificatePublicKey;
	private Certificatex509v3Extension certificateV3Extension;
	public Certificatex509v3(int version, CertificateSubject certificateSubject, String serialNumber,
			CertificateValidity certificateValidity, CertificatePublicKey certificatePublicKey,
			Certificatex509v3Extension certificateV3Extension) {
		super();
		this.version = version;
		this.certificateSubject = certificateSubject;
		this.serialNumber = serialNumber;
		this.certificateValidity = certificateValidity;
		this.certificatePublicKey = certificatePublicKey;
		this.certificateV3Extension = certificateV3Extension;
	}
	public int getVersion() {
		return version;
	}
	public CertificateSubject getCertificateSubject() {
		return certificateSubject;
	}
	public String getSerialNumber() {
		return serialNumber;
	}
	public CertificateValidity getCertificateValidity() {
		return certificateValidity;
	}
	public CertificatePublicKey getCertificatePublicKey() {
		return certificatePublicKey;
	}
	public Certificatex509v3Extension getCertificateV3Extension() {
		return certificateV3Extension;
	}
	
	
}
