package implementation;

import java.io.File;
import java.util.Enumeration;
import java.util.List;

import code.GuiException;
import x509.v3.CodeV3;

public class MyCode extends CodeV3 {

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
	public int loadKeypair(String arg0) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public Enumeration<String> loadLocalKeystore() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean removeKeypair(String arg0) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void resetLocalKeystore() {
		// TODO Auto-generated method stub

	}

	@Override
	public boolean saveKeypair(String arg0) {

		return false;
	}

	@Override
	public boolean signCertificate(String arg0, String arg1) {
		// TODO Auto-generated method stub
		return false;
	}

}
