package implementation;

import java.util.List;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

public class MyKeyStore {
	private KeyStore  keyStore = null;
	private PKCS10CertificationRequest certificateSignRequest = null;
	private static final char [] ARR_PASSWORD = "Baba1234!".toCharArray();
	private static final String KEY_STORE_NAME = "KeyStore.jks";
	private static final String KEY_STORE_DEFAULT_JAVA_NAME = "JKS";
	private static final String KEY_STORE_FORMAT_PKCS12 = "PKCS12";
	private static final String CERTIFICATE_TYPE = "X.509";
	private String aliasToSign = null;
	private String selectedAlias = null;
	
	private static final HashMap<String, String> algSig = new HashMap<>();
	
	static 
	{
		algSig.put("1.3.36.3.3.1.3", "RIPEMD128withRSA");
		algSig.put("1.3.36.3.3.1.2", "RIPEMD160withRSA");
		algSig.put("1.3.36.3.3.1.4", "RIPEMD256withRSA");
		Security.addProvider(new BouncyCastleProvider());
	}
	
	private static boolean checkIfExist(String fileName)
	{
		File file = new File(fileName);
		return file.exists();
	}
	
	private KeyStore getKeyStore()
	{
		if (keyStore == null)
		{
			if (!loadKeyStore())
			{
				return null;
			}
		}
		return keyStore;
	}
	
	public boolean loadKeyStore()
	{
		FileInputStream fileInputStream  = null;
		try 
		{
			keyStore = KeyStore.getInstance(KEY_STORE_DEFAULT_JAVA_NAME);
			if (!checkIfExist(KEY_STORE_NAME))
			{
				keyStore.load(null, null);
			}
			else
			{
				fileInputStream = new FileInputStream(KEY_STORE_NAME);
				keyStore.load(fileInputStream, ARR_PASSWORD);
			}
		} 
		catch (KeyStoreException | NoSuchAlgorithmException 
				| CertificateException | IOException e)
		{
			return false;
		}
		finally 
		{
			if (fileInputStream != null)
			{
				try {
					fileInputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return true;
	}
	
	private boolean saveKeyStore()
	{
		FileOutputStream fileOutputStream = null;
		try {
			fileOutputStream = new FileOutputStream(KEY_STORE_NAME);
			keyStore.store(fileOutputStream, ARR_PASSWORD);
		} catch (KeyStoreException | NoSuchAlgorithmException 
				| CertificateException | IOException e) {
			e.printStackTrace();
			return false;
		}
		finally {
			if (fileOutputStream != null)
			{
				try {
					fileOutputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
					return false;
				}
			}
		}
		return true;
	}
	
	private void deleteKeyStore()
	{
		if (checkIfExist(KEY_STORE_NAME))
		{
			File file = new File(KEY_STORE_NAME);
			file.delete();
			keyStore = null;
		}
	}
	
	private static KeyPair generateKeyPair(CertificatePublicKey certificatePublicKey)
	{
		String algorithm = certificatePublicKey.getPublicKeyAlgorithm();
		int keySize = certificatePublicKey.getPublicKeyLength();
		KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
			keyPairGenerator.initialize(keySize);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			return keyPair;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	private static GeneralNames generateIssuerAlternativeNames(String names)
	{
		String[] alternativeNames = names.split("\\s+");
		GeneralName[]  gmAlternativeNames = new GeneralName[alternativeNames.length];
		int idx = 0;
		
		for (String it : alternativeNames)
		{
			gmAlternativeNames[idx++] = new GeneralName(GeneralName.dNSName, it);
		}
		
		GeneralNames gAlternativeNames = new GeneralNames(gmAlternativeNames);
		return gAlternativeNames;
	}
	
	private static void addRdnToNameBuilder(X500NameBuilder builder, ASN1ObjectIdentifier style, String name)
	{
		if (!"".equals(name))
		{
			builder.addRDN(style, name);
		}
	}
	
	private static X509Certificate generateCertificate(KeyPair keyPair, Certificatev3 certificatev3)
	{
		// builder for extension 
		X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
		addRdnToNameBuilder(x500NameBuilder, BCStyle.C, certificatev3.getCertificateSubject().getCountry());
		addRdnToNameBuilder(x500NameBuilder, BCStyle.ST, certificatev3.getCertificateSubject().getState());
		addRdnToNameBuilder(x500NameBuilder, BCStyle.L, certificatev3.getCertificateSubject().getLocality());
		addRdnToNameBuilder(x500NameBuilder, BCStyle.O, certificatev3.getCertificateSubject().getOrganization());
		addRdnToNameBuilder(x500NameBuilder, BCStyle.OU, certificatev3.getCertificateSubject().getOrganizationUnit());
		addRdnToNameBuilder(x500NameBuilder, BCStyle.CN, certificatev3.getCertificateSubject().getCommonName());
		
		X500Name x500Name = x500NameBuilder.build();
		X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
				x500Name, /* issuer */
				new BigInteger(certificatev3.getSerialNumber()), /* serial number */
				certificatev3.getCertificateValidity().getNotBefore(), /* not before */
				certificatev3.getCertificateValidity().getNotAfter(), /* not after */
				x500Name, /* subject */
				keyPair.getPublic() /* public key*/
				);
		
		// BASIC CONSTRAINTS
		BasicConstraints basicConstraints = null;
		if (certificatev3.getCertificateV3Extension().getExtBasicConstraint().isCertificateAuthority())
		{
			int pathLen = Integer.parseInt(certificatev3.getCertificateV3Extension().getExtBasicConstraint().getPathLength());
			basicConstraints = new BasicConstraints(pathLen);
		}
		else
		{
			basicConstraints = new BasicConstraints(false);
		}
		try 
		{
			certificateBuilder.addExtension(Extension.basicConstraints, 
											certificatev3.getCertificateV3Extension().getExtBasicConstraint().isCritical(),
											basicConstraints);
		} catch (CertIOException e1) {
			e1.printStackTrace();
			return null;
		}
		
		// KEY IDENTIFIERS
		if (certificatev3.getCertificateV3Extension().getExtKeyIdentifiers().isKeyIdentifierEnabled())
		{
			try {
				JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
				certificateBuilder.addExtension(Extension.subjectKeyIdentifier, 
												certificatev3.getCertificateV3Extension().getExtKeyIdentifiers().isCritical(),
												extensionUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
			} catch (CertIOException e2) {
				e2.printStackTrace();
				return null;
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
				return null;
			}
			
		}
		
		// ALTERNATIVE NAMES
		// There are alternative names
		if (certificatev3.getCertificateV3Extension().getExtIssuerAlternativeNames().getIssuerAlternativeNames().length != 0)
		{
			GeneralNames generalNames = generateIssuerAlternativeNames(certificatev3.getCertificateV3Extension().getExtIssuerAlternativeNames().getIssuerAlternativeNames()[0]);
			try {
				certificateBuilder.addExtension(X509Extensions.IssuerAlternativeName, 
												certificatev3.getCertificateV3Extension().getExtIssuerAlternativeNames().isCritical(), 
												generalNames);
			} catch (CertIOException e1) {
				e1.printStackTrace();
				return null;
			};
		}
		
		ContentSigner contentSigner = null;
		try {
			contentSigner = new JcaContentSignerBuilder(certificatev3.getCertificateSubject().getSignatureAlgorithm()).
											build(keyPair.getPrivate());
		} catch (OperatorCreationException e) {
			e.printStackTrace();
			return null;
		};
		X509CertificateHolder certificateHolder = certificateBuilder.build(contentSigner);
		
		X509Certificate certificate = null;
		try {
			certificate = new JcaX509CertificateConverter().getCertificate(certificateHolder);
		} catch (CertificateException e) {
			e.printStackTrace();
			return null;
		}
		return certificate;
		
	}

	public boolean generateKeyPairCertificate(String alias, Certificatev3 certificatev3) {
		KeyPair keyPair = generateKeyPair(certificatev3.getCertificatePublicKey());
		X509Certificate  certificate = generateCertificate(keyPair, certificatev3);
		// Error in generating certificate.
		//
		if (certificate == null)
		{
			return false;
		}
		Certificate [] chainCertficate = new Certificate[1];
		chainCertficate[0] = certificate;
		
		try {
			if (getKeyStore() == null)
			{
				return false;
			}
			getKeyStore().setKeyEntry(alias, keyPair.getPrivate(), ARR_PASSWORD, chainCertficate);
			if (!saveKeyStore())
			{
				return false;
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return false;
			
		}
		return true;
	}
	
	public boolean removeKeyPairCertificate(String alias)
	{
		if (getKeyStore() == null)
		{
			return false;
		}
		try {
			getKeyStore().deleteEntry(alias);
			if (!saveKeyStore())
			{
				return false;
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}
	
	public Enumeration<String> loadLocalKeyStore()
	{
		if (!loadKeyStore())
		{
			return null;
		}
		try 
		{
			return getKeyStore().aliases();
		}
		catch (KeyStoreException exception)
		{
			exception.printStackTrace();
			return null;
		}
	}
	
	public void resetLocalKeyStore()
	{
		deleteKeyStore();
	}
	
	private static String getFromRDNString(RDN rdn)
	{
		return IETFUtils.valueToString(rdn.getFirst().getValue());
	}
	
	private static String getStringWithStyle(X500Name x500Name, ASN1ObjectIdentifier style)
	{
		RDN [] rdnArr = x500Name.getRDNs(style);
		RDN rdn = null;
		if ( (rdnArr == null) || (rdnArr.length == 0))
		{
			return "";
		}

		rdn = rdnArr[0];
		return getFromRDNString(rdn);
	}
	
	private static String byteArrayToHex(byte[] byteArr) 
	{  
		char[] hexArrDigit = "0123456789ABCDEF".toCharArray(); 
		char[] hexCharArray = new char[byteArr.length * 2];
		int idx;
		int byteVal;
		for (idx = 0; idx < byteArr.length; idx++) 
		{ 
			byteVal = 0xFF & byteArr[idx]; 
			hexCharArray[idx * 2] = hexArrDigit[byteVal >>> 4]; 
			hexCharArray[idx * 2 + 1] = hexArrDigit[byteVal & 0x0F]; 
		  } 
		return new String(hexCharArray); 
	}
	
	private static String getSubjectKeyIdentifier(X509Certificate certificate) {
		// https://stackoverflow.com/questions/6523081/why-doesnt-my-key-identifier-match
		byte[] extension = certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());
		byte[] subjectKeyIdentifier = {};
		ASN1Primitive primitive;
		if (extension == null) {
			return "";
		}

		try {
			primitive = JcaX509ExtensionUtils.parseExtensionValue(extension);
			subjectKeyIdentifier = ASN1OctetString.getInstance(primitive.getEncoded()).getOctets();
		} catch (IOException e1) {
			e1.printStackTrace();
			return null;
		}
		return byteArrayToHex(subjectKeyIdentifier).replaceAll("..(?!$)", "$0:");
	}
	
	private static String getSerialNumberKeyIdentifier(X509Certificate certificate)
	{
		byte[] extension = certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
		byte[] authorityKeyIdentifier = {};
		ASN1Primitive primitive;
		if (extension == null) {
			return "";
		}

        ASN1OctetString oct;
        AuthorityKeyIdentifier authID = null;
		try {
			oct = (ASN1OctetString)ASN1Primitive.fromByteArray(extension);
			authID = AuthorityKeyIdentifier.getInstance(ASN1Primitive.fromByteArray(oct.getOctets()));
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
        
        BigInteger big = authID.getAuthorityCertSerialNumber();
        return big.toString();
	}
	
	private static String getIssuerKeyIdentifier(X509Certificate certificate)
	{
		byte[] extension = certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
		byte[] authorityKeyIdentifier = {};
		ASN1Primitive primitive;
		if (extension == null) {
			return "";
		}

        ASN1OctetString oct;
        AuthorityKeyIdentifier authID = null;
		try {
			oct = (ASN1OctetString)ASN1Primitive.fromByteArray(extension);
			authID = AuthorityKeyIdentifier.getInstance(ASN1Primitive.fromByteArray(oct.getOctets()));
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
        
        GeneralNames generalNames = authID.getAuthorityCertIssuer();
        GeneralName[] geNames = generalNames.getNames();
        String name = geNames[0].getName().toString();
        
        return name;
	}
	
	
	private static String getAuthorityKeyIdentifier(X509Certificate certificate)
	{
		
		byte[] extension = certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
		byte[] authorityKeyIdentifier = {};
		ASN1Primitive primitive;
		if (extension == null) {
			return "";
		}

        ASN1OctetString oct;
        AuthorityKeyIdentifier authID = null;
		try {
			oct = (ASN1OctetString)ASN1Primitive.fromByteArray(extension);
			authID = AuthorityKeyIdentifier.getInstance(ASN1Primitive.fromByteArray(oct.getOctets()));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
        

        BigInteger big = authID.getAuthorityCertSerialNumber();
        GeneralNames generalName = authID.getAuthorityCertIssuer();

        byte[] keyID = authID.getKeyIdentifier();
        if (keyID != null)
        {
        	authorityKeyIdentifier = authID.getKeyIdentifier();
        }
		return byteArrayToHex(authorityKeyIdentifier).replaceAll("..(?!$)", "$0:");
	}
	
	private static Set<String> getSetCriticalExtFromCert(X509Certificate certificate)
	{
		Set<String> setCriticalOID = certificate.getCriticalExtensionOIDs();
		if (setCriticalOID == null)
		{
			setCriticalOID = new LinkedHashSet<String>();
		}
		return setCriticalOID;
	}
	
	private static Certificatev3ExtensionBasicConstraint getExtBasicConstraintFromCert(X509Certificate certificate)
	{
		Set<String> setCriticalOID = getSetCriticalExtFromCert(certificate);
		@SuppressWarnings("deprecation")
		boolean isCriticalBasicConstraint = setCriticalOID.contains(X509Extensions.BasicConstraints.getId());
		
		boolean isCertificateAuthority = false;
		int pathLength = certificate.getBasicConstraints();
		String pathLengthStr = null;
		if (pathLength != -1)
		{
			isCertificateAuthority = true;
			pathLengthStr = Integer.toString(pathLength);
		}
		else
		{
			isCertificateAuthority = false;
			pathLengthStr =  "";
		}
		
		Certificatev3ExtensionBasicConstraint basicConstraint = new Certificatev3ExtensionBasicConstraint(isCriticalBasicConstraint, pathLengthStr, isCertificateAuthority);
		return basicConstraint;
	}
	
	private static Certificatev3ExtensionIssuerAlternativeName getExtAltNamesFromCert(X509Certificate certificate)
	{
		Set<String> setCriticalOID = getSetCriticalExtFromCert(certificate);
		boolean isCriticalAlternativeNames = setCriticalOID.contains(X509Extensions.IssuerAlternativeName.getId());
		
		String issuerAlternativeNames[] = new String[0]; 
		try {
			Collection<?> collectionAltNames = certificate.getIssuerAlternativeNames();
			if (collectionAltNames != null)
			{
				issuerAlternativeNames = new String[1];
				issuerAlternativeNames[0] = "";
				Iterator it = certificate.getIssuerAlternativeNames().iterator();
				while (it.hasNext())
				{
					List list = (List)it.next();
					if (list.get(0).equals(GeneralName.dNSName))
					{
						issuerAlternativeNames[0] +=  " " + (String)list.get(1);
						
					}
				}
			}
		} catch (CertificateParsingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		
		Certificatev3ExtensionIssuerAlternativeName alternativeNames = 
				new Certificatev3ExtensionIssuerAlternativeName(
						isCriticalAlternativeNames, 
						issuerAlternativeNames);
		return alternativeNames;
	}
	
	private static Certificatev3ExtensionKeyIdentifiers getExtKeyIdentifiersFromCert(X509Certificate certificate)
	{
		Set<String> setCriticalOID = getSetCriticalExtFromCert(certificate);
		boolean isCriticalKeyIdentifier = setCriticalOID.contains(X509Extensions.SubjectKeyIdentifier.getId());

		boolean isKeyIdentifierEnabled = false;
		String keySubjectIdentifier = null;
		String keyAuthorityIdentifier = null;
		String issuer = "";
		String serialNumber = "";
		
		keySubjectIdentifier = getSubjectKeyIdentifier(certificate);
		keyAuthorityIdentifier = getAuthorityKeyIdentifier(certificate);
		serialNumber = getSerialNumberKeyIdentifier(certificate);
		issuer = getIssuerKeyIdentifier(certificate);
		if (!"".equals(keySubjectIdentifier))
		{
			isKeyIdentifierEnabled = true;
		}
		else 
		{
			isKeyIdentifierEnabled = false;
		}
		
		Certificatev3ExtensionKeyIdentifiers keyIdentifiers = new Certificatev3ExtensionKeyIdentifiers(
															isCriticalKeyIdentifier, 
															isKeyIdentifierEnabled, 
															keySubjectIdentifier, 
															keyAuthorityIdentifier,
															issuer,
															serialNumber);
		return keyIdentifiers;
	}
	
	public static String getSignatureAlgorithm(X509Certificate certificate)
	{
		String signCode = certificate.getSigAlgName();
		String algName = algSig.get(signCode); 
		if (algName == null)
		{
			return signCode;
		}
		return algName;
	}
	
	private CertificateIssuer getIssuerFromCert(Certificate[] certificateChain, Certificate certificate) {
		X500Name issuerX500Name = null;
		X509Certificate issuerCertificate = null;
		String issuerAlgorithm = null;
		if (certificateChain == null)
		{
			try {
				issuerX500Name = new JcaX509CertificateHolder((X509Certificate) certificate).getIssuer();
				issuerAlgorithm = "NOT KNOWN";
			} catch (CertificateEncodingException e) {
				e.printStackTrace();
				return null;
			}
		}
		else
		{
			if (certificateChain.length == 1)
			{
				issuerCertificate = (X509Certificate)certificateChain[0];
			}
			else
			{
				issuerCertificate = (X509Certificate)certificateChain[1];
			}
			
			try {
				issuerX500Name = new JcaX509CertificateHolder(issuerCertificate).getSubject();
				issuerAlgorithm = issuerCertificate.getSigAlgName();
				
			} catch (CertificateEncodingException e) {
				e.printStackTrace();
				return null;
			}
		}
		
		
		
		CertificateIssuer issuer = new CertificateIssuer(
				issuerX500Name.toString(), 
				issuerAlgorithm);
		return issuer;
			
	}
	
	private int getCertificateType(String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException
	{
		int type;
		if (getKeyStore().getKey(alias, ARR_PASSWORD) == null)
		{
			type = Certificatev3.TYPE_TRUSTED;
		}
		else
		{
			if (getKeyStore().getCertificateChain(alias).length == 1)
			{

				type = Certificatev3.TYPE_KEY_PAIR;
			}
			else 
			{
				type = Certificatev3.TYPE_SIGNED;
			}
		}

		return type;
	}

	
	public Certificatev3 loadKeyPair(String alias)
	{
		String country = null;
		String state = null;
		String locality = null;
		String organization = null;
		String organizationUnit = null;
		String commonName = null;
		String signatureAlgorithm = null;
		
		Integer publicKeyLength = null;
		String publicKeyAlgorithm = null;
		
		Integer version = null;
		String serialNumber = null;
		Date notBefore = null;
		Date notAfter = null;
		if (getKeyStore() == null)
		{
			return null;
		}
		Certificatev3 certificateV3 = null;
		try {
			X509Certificate certificate = null;
			certificate =  (X509Certificate)getKeyStore().getCertificate(alias);
			Certificate[] certificateChain = getKeyStore().getCertificateChain(alias);
			X500Name x500name = new JcaX509CertificateHolder(certificate).getSubject();
			
			// SUBJECT DATA
			country = getStringWithStyle(x500name, BCStyle.C);
			state = getStringWithStyle(x500name, BCStyle.ST);
			locality = getStringWithStyle(x500name, BCStyle.L);
			organization = getStringWithStyle(x500name, BCStyle.O);
			organizationUnit = getStringWithStyle(x500name, BCStyle.OU);
			commonName = getStringWithStyle(x500name, BCStyle.CN);
			signatureAlgorithm = getSignatureAlgorithm(certificate);

			
			CertificateSubject certificateSubject = new CertificateSubject(country, state, locality, organization, 
					organizationUnit, commonName, signatureAlgorithm);
			
			version = certificate.getVersion() - 1;
			serialNumber = ""+certificate.getSerialNumber();
			
			// DATE VALIDITY 
			notBefore = certificate.getNotBefore();
			notAfter = certificate.getNotAfter();
			CertificateValidity certificateValidity = new CertificateValidity(notBefore, notAfter);
			
			// PUBLIC KEY
			publicKeyAlgorithm = certificate.getPublicKey().getAlgorithm();
			RSAPublicKey rsaPublicKey = (RSAPublicKey)certificate.getPublicKey();
			publicKeyLength = rsaPublicKey.getModulus().bitLength();
			CertificatePublicKey certificatePublicKey = new CertificatePublicKey(publicKeyAlgorithm, 
					publicKeyLength);
			
			// ISSUED BY
			
			CertificateIssuer issuer = getIssuerFromCert(certificateChain, certificate);
			
			Certificatev3ExtensionBasicConstraint basicConstraint = getExtBasicConstraintFromCert(certificate);
			Certificatev3ExtensionKeyIdentifiers keyIdentifiers = getExtKeyIdentifiersFromCert(certificate);
			Certificatev3ExtensionIssuerAlternativeName alternativeNames =  getExtAltNamesFromCert(certificate);
			
			Certificatev3Extension certificatev3Extension = new Certificatev3Extension(basicConstraint, alternativeNames, keyIdentifiers);
			int type = getCertificateType(alias);
			
			
			certificateV3 = new Certificatev3(version, certificateSubject, 
					serialNumber, issuer, certificateValidity, certificatePublicKey, 
					certificatev3Extension,type);
		} catch (KeyStoreException | CertificateEncodingException | 
				UnrecoverableKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
		selectedAlias = alias;
		return certificateV3;
	}


	public boolean exportKeypair(String alias, String file, String password) 
	{
		FileOutputStream fileOutputStream = null;
		
		try {
			
			Certificate[] chainCertificate = getKeyStore().getCertificateChain(alias);
			Key key = getKeyStore().getKey(alias, ARR_PASSWORD);
			fileOutputStream = new FileOutputStream(file);
			KeyStore keyStore = KeyStore.getInstance(KEY_STORE_FORMAT_PKCS12);
			keyStore.load(null, null);			
			keyStore.setKeyEntry(alias, key, password.toCharArray(), chainCertificate);
			keyStore.store(fileOutputStream, password.toCharArray());
		} catch (KeyStoreException | UnrecoverableKeyException | 
				NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
			return false;
		}
		finally {
			if (fileOutputStream != null)
			{
				try 
				{
					fileOutputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
					return false;
				}
			}
		}
		return true;
	}
	
	// password - password which is used for encrypting key and keystore.
	//
	public 	boolean importKeyPair(String alias, String file, String password)
	{
		FileInputStream fileInputStream = null;
		KeyStore keyStore = null;
		
		try 
		{
			keyStore = KeyStore.getInstance(KEY_STORE_FORMAT_PKCS12);
			fileInputStream = new FileInputStream(file);
			keyStore.load(fileInputStream, password.toCharArray());
			
			Certificate [] chainCertficate = keyStore.getCertificateChain(alias);
			Key key = keyStore.getKey(alias, password.toCharArray());
			getKeyStore().setKeyEntry(alias, key, ARR_PASSWORD, chainCertficate);
			saveKeyStore();
			
		}
		catch (KeyStoreException | NoSuchAlgorithmException | 
				CertificateException | IOException | UnrecoverableKeyException e)
		{
			e.printStackTrace();
			return false;
		}
		
		return true;
	}

	public boolean generateCSR(String keypairName) {
		try {
			PrivateKey privateKey  = (PrivateKey) getKeyStore().getKey(keypairName, ARR_PASSWORD);
			X509Certificate certificate = (X509Certificate) getKeyStore().getCertificate(keypairName);
			X500Name x500SubjectName = new JcaX509CertificateHolder(certificate).getSubject();
			PKCS10CertificationRequestBuilder certificationRequestBuilder = 
											new JcaPKCS10CertificationRequestBuilder(
												x500SubjectName, 
												certificate.getPublicKey());
			Extensions extensions = new JcaX509CertificateHolder(certificate).getExtensions();
			certificationRequestBuilder.addAttribute(
					PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, 
					extensions);
			ContentSigner contentSigner = new JcaContentSignerBuilder(getSignatureAlgorithm(certificate)).build(privateKey);
			certificateSignRequest =  certificationRequestBuilder.build(contentSigner);
			aliasToSign = keypairName;
			
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateEncodingException | OperatorCreationException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	public List<String> getIssuers(String keypairName) {
		LinkedList<String> listCertifiedAuthorities = new LinkedList<>();
		try {
			Enumeration<String> enumCertificas = getKeyStore().aliases();
			while (enumCertificas.hasMoreElements())
			{
				String alias = enumCertificas.nextElement();
				X509Certificate certificate = (X509Certificate) getKeyStore().getCertificate(alias);
				Certificatev3ExtensionBasicConstraint extBasic = getExtBasicConstraintFromCert(certificate);
				if (extBasic.isCertificateAuthority())
				{
					listCertifiedAuthorities.addLast(alias);
				}
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return null;
		}
		return listCertifiedAuthorities;
	}

	public String getIssuer(String issuerAlias) {
		X509Certificate certificate;
		try {
			certificate = (X509Certificate) getKeyStore().getCertificate(issuerAlias);
			X500Name x500SubjectName = new JcaX509CertificateHolder(certificate).getSubject();
			String subjectNameStringRep = x500SubjectName.toString();
			return subjectNameStringRep;
		} catch (KeyStoreException | CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
		
	}

	public String getIssuerPublicKeyAlgorithm(String issuerAlias) {
		X509Certificate certificate;
		try {
			certificate = (X509Certificate) getKeyStore().getCertificate(issuerAlias);
			String publicKeyAlgorithm = certificate.getPublicKey().getAlgorithm();
			return publicKeyAlgorithm;
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}

	private LinkedList<Extension> getListExtensionsFromCSR()
	{
		LinkedList<Extension> listExtensions = new LinkedList<>();
		Attribute[] attributes = null;
		Attribute attribute = null;
		DERSet set = null;
		Enumeration<Extensions> enumList = null;
		Extensions extensions = null;
		Extension ext = null;
		
		attributes = certificateSignRequest.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
		attribute = attributes[0];
		set = (DERSet) attribute.getAttrValues();
		enumList = set.getObjects();
		
		if (enumList.hasMoreElements())
		{
			extensions = enumList.nextElement();
			ASN1ObjectIdentifier[] oidExt = extensions.getExtensionOIDs();
			for (ASN1ObjectIdentifier itObjId : oidExt)
			{
				ext = extensions.getExtension(itObjId);
				listExtensions.addLast(ext);
			}
		}
		return listExtensions;
		
	}
	
	
	private boolean changeCertificateIssuer(X509Certificate certificateSigned, String issuerAlias, String aliasToSign)
	{
		Key keySigned;
		try {
			keySigned = keyStore.getKey(aliasToSign, ARR_PASSWORD);
			removeKeyPairCertificate(aliasToSign);
			Certificate[] chainCertificateCA = getKeyStore().getCertificateChain(issuerAlias); 
			Certificate[] chainCertficateSigned = new Certificate[1 + chainCertificateCA.length];
			for (int idx = 0; idx < chainCertificateCA.length; idx ++)
			{
				chainCertficateSigned[idx + 1] = chainCertificateCA[idx];
			}
			chainCertficateSigned[0] = certificateSigned;
			getKeyStore().setKeyEntry(aliasToSign, keySigned, ARR_PASSWORD, chainCertficateSigned);
			saveKeyStore();
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}
	
	public boolean signCertificate(String issuerAlias, String algorithmSign) {
		
		try {
			// PREPARE CA FOR SIGN
			PrivateKey privateKeyCA = (PrivateKey)getKeyStore().getKey(issuerAlias, ARR_PASSWORD);
			X509Certificate certificateCA = (X509Certificate)getKeyStore().getCertificate(issuerAlias);
			X509Certificate certificateToSign = (X509Certificate)getKeyStore().getCertificate(aliasToSign);

			// GENERATE CERT TO SIGN
			X500Name x500NameToSign = certificateSignRequest.getSubject();
			X500Name x500nameCA = new JcaX509CertificateHolder(certificateCA).getSubject();
			JcaPKCS10CertificationRequest jcaRequest = new JcaPKCS10CertificationRequest(certificateSignRequest);
			
			X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
					x500nameCA, 
					certificateToSign.getSerialNumber(), 
					certificateToSign.getNotBefore(), 
					certificateToSign.getNotAfter(), 
					x500NameToSign, 
					jcaRequest.getPublicKey());
			
			JcaContentSignerBuilder contentSignerBuilderCA =  new JcaContentSignerBuilder(algorithmSign);
			ContentSigner contentSignerCA = contentSignerBuilderCA.build(privateKeyCA);
			LinkedList<Extension> listExtension = getListExtensionsFromCSR();
			
			for (Extension it : listExtension)
			{
				certificateBuilder.addExtension(it);
			}
			
			JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
			
			Set<String> setCriticalOID = getSetCriticalExtFromCert(certificateToSign);
			boolean isCriticalKeyIdentifier = setCriticalOID.contains(X509Extensions.SubjectKeyIdentifier.getId());
			  
			GeneralName[]  names = new GeneralName[1];
			int idx = 0;
			
			names[idx++] = new GeneralName(GeneralName.dNSName, x500nameCA.toString());
			
			GeneralNames gAlternativeNames = new GeneralNames(names);
			
			
			AuthorityKeyIdentifier authorityKeyIdentifier = extensionUtils.createAuthorityKeyIdentifier(certificateCA.getPublicKey(), gAlternativeNames, certificateCA.getSerialNumber());
			certificateBuilder.addExtension(Extension.authorityKeyIdentifier, 
						isCriticalKeyIdentifier,
						authorityKeyIdentifier);
			
			X509CertificateHolder certificateHolder = certificateBuilder.build(contentSignerCA);
			X509Certificate certificateSigned = new JcaX509CertificateConverter().getCertificate(certificateHolder);
			
			return changeCertificateIssuer(certificateSigned, issuerAlias, aliasToSign);
			
		} catch (OperatorCreationException | UnrecoverableKeyException | KeyStoreException 
				| NoSuchAlgorithmException | InvalidKeyException | CertIOException | CertificateException e) {
			e.printStackTrace();
			return false;
		}
	}
	
	private static final int ENCODING_DER = 0;
	private static final int ENCODING_PEM = 1;

	private static boolean outputCertificateToDER(File file, X509Certificate certificate)
	{
		FileOutputStream fileOutputStream = null;
		byte[] outputBytes = null;
		try 
		{
			outputBytes = certificate.getEncoded();
			fileOutputStream = new FileOutputStream(file);
			fileOutputStream.write(outputBytes);
		} catch (CertificateEncodingException | IOException e) {
			e.printStackTrace();
			return false;
		}
		finally {
			if (fileOutputStream != null)
			{
				try {
					fileOutputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
					return false;
				}
			}
		}
		return true;
	}
	
	private static boolean outputCertificateToPEM(File file, X509Certificate certificate) {
		FileWriter fileWriter = null;
		JcaPEMWriter pemWriter = null;
		try 
		{
			fileWriter = new FileWriter(file);
			pemWriter = new JcaPEMWriter(fileWriter);
			pemWriter.writeObject(certificate);
			pemWriter.flush();
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
		finally {
			if (fileWriter != null)
			{
				try {
					fileWriter.close();
				} catch (IOException e) {
					e.printStackTrace();
					return false;
				}
			}
			if (fileWriter != null)
			{
				try {
					pemWriter.close();
				} catch (IOException e) {
					e.printStackTrace();
					return false;
				}
			}
		}
		return true;
	}
	
	public boolean exportCertificate(File file, int encoding) {
		X509Certificate certificate = null;

		switch (encoding)
		{
			case ENCODING_DER:
				try {
					certificate = (X509Certificate) getKeyStore().getCertificate(selectedAlias);
				} catch (KeyStoreException e) {
					e.printStackTrace();
					return false;
				}
				return outputCertificateToDER(file, certificate);
			case ENCODING_PEM:
				try {
					certificate = (X509Certificate) getKeyStore().getCertificate(selectedAlias);
				} catch (KeyStoreException e) {
					e.printStackTrace();
					return false;
				}
				return outputCertificateToPEM(file, certificate);
			default:
				return false;
		}
	}

	public boolean importCertificate(File file, String keyPairName) {
		FileInputStream fileInputStream = null;
		BufferedInputStream bufferedInputStream = null;
		
	    try {
	    	fileInputStream = new FileInputStream(file);
			bufferedInputStream = new BufferedInputStream(fileInputStream);
			CertificateFactory cf = CertificateFactory.getInstance(CERTIFICATE_TYPE);
			
			Certificate certificate = cf.generateCertificate(bufferedInputStream);
			getKeyStore().setCertificateEntry(keyPairName, certificate);
			saveKeyStore();
		} catch (CertificateException | FileNotFoundException | KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
	    finally {
			if (fileInputStream != null)
			{
				try {
					fileInputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
					return false;
				}
			}
		}
		return true;
	}



}
