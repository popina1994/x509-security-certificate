package implementation;

import java.io.File;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;

import code.GuiException;
import x509.v3.CodeV3;

public class MyCode extends CodeV3 {
	private static MyKeyStore myKeyStore = new MyKeyStore();
	
	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf) throws GuiException {
		super(algorithm_conf, extensions_conf);
		// TODO Auto-generated constructor stub
	}

	@Override
	public boolean exportCertificate(File arg0, int arg1) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean exportKeypair(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub	
		return false;
	}

	@Override
	public boolean generateCSR(String arg0) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String getIssuer(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getIssuerPublicKeyAlgorithm(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<String> getIssuers(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int getRSAKeyLength(String arg0) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public boolean importCertificate(File arg0, String arg1) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean importKeypair(String arg0, String arg1, String arg2) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public int loadKeypair(String alias) {
		
		return 0;
	}

	@Override
	public Enumeration<String> loadLocalKeystore() {
		return myKeyStore.loadLocalKeyStore();
	}

	@Override
	public boolean removeKeypair(String alias) {
		return myKeyStore.removeKeyPairCertificate(alias);
	}

	@Override
	public void resetLocalKeystore() {
		myKeyStore.resetLocalKeyStore();
	}

	@Override
	public boolean saveKeypair(String alias) {
		String country = access.getSubjectCountry();
		String state = access.getSubjectState();
		String locality = access.getSubjectLocality();
		String organization = access.getSubjectLocality();
		String organizationUnit = access.getSubjectOrganizationUnit();
		String commonName = access.getSubjectCommonName();
		String signatureAlgorithm = access.getPublicKeySignatureAlgorithm();
		CertificateSubject certificateSubject = new CertificateSubject(country, state, locality, 
				organization, organizationUnit, commonName, signatureAlgorithm);
		
		int version = access.getVersion();
		
		String serialNumber = access.getSerialNumber();
		
		Date notBefore = access.getNotBefore();
		Date notAfter = access.getNotAfter();
		CertificateValidity certificateValidity = new CertificateValidity(notBefore, notAfter);
		
		String publicKeyLength = access.getPublicKeyParameter();
		String publicKeyAlgorithm  = access.getPublicKeyAlgorithm();
		int intPublicKeyLength = Integer.parseInt(publicKeyLength);
		
		CertificatePublicKey certificatePublicKey = new CertificatePublicKey(publicKeyAlgorithm, intPublicKeyLength);
		Certificatex509v3Extension certificateV3Extension = null;
		
		Certificatex509v3 certificatex509v3 = new Certificatex509v3(version, certificateSubject, 
											serialNumber, certificateValidity, 
											certificatePublicKey, certificateV3Extension);
		return myKeyStore.generateKeyPairCertificate(alias, certificatex509v3);
	}

	@Override
	public boolean signCertificate(String arg0, String arg1) {
		// TODO Auto-generated method stub
		return false;
	}

}
