package implementation;

public class Certificatev3 {
	public static final int TYPE_ERROR = -1;
	public static final int TYPE_KEY_PAIR = 0;
	public static final int TYPE_SIGNED = 1;
	public static final int TYPE_TRUSTED = 2;
	
	private int version;
	private CertificateSubject certificateSubject;
	private String serialNumber;
	private CertificateIssuer certificateIssuer;
	private CertificateValidity certificateValidity;
	private CertificatePublicKey certificatePublicKey;
	private Certificatev3Extension certificateV3Extension;
	
	private int type;
	
	public Certificatev3(int version, CertificateSubject certificateSubject, String serialNumber,
			CertificateValidity certificateValidity, CertificatePublicKey certificatePublicKey,
			Certificatev3Extension certificateV3Extension) {
		super();
		this.version = version;
		this.certificateSubject = certificateSubject;
		this.serialNumber = serialNumber;
		this.certificateValidity = certificateValidity;
		this.certificatePublicKey = certificatePublicKey;
		this.certificateV3Extension = certificateV3Extension;
	}
	
	public Certificatev3(int version, CertificateSubject certificateSubject, String serialNumber,
			CertificateIssuer certificateIssuer, CertificateValidity certificateValidity,
			CertificatePublicKey certificatePublicKey, Certificatev3Extension certificateV3Extension, int type) {
		super();
		this.version = version;
		this.certificateSubject = certificateSubject;
		this.serialNumber = serialNumber;
		this.certificateIssuer = certificateIssuer;
		this.certificateValidity = certificateValidity;
		this.certificatePublicKey = certificatePublicKey;
		this.certificateV3Extension = certificateV3Extension;
		this.type = type;
	}

	public int getType() {
		return type;
	}

	public CertificateIssuer getCertificateIssuer() {
		return certificateIssuer;
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
	public Certificatev3Extension getCertificateV3Extension() {
		return certificateV3Extension;
	}
}
