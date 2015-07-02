/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: OpenSSLFIPSProvider.java 293 2013-12-19 15:49:22Z tejohnson $
 * 
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 293 $ 
 * 
 * Changed: $LastChangedDate: 2013-12-19 10:49:22 -0500 (Thu, 19 Dec 2013) $
 *****************************************************************************/

package org.keysupport.provider;

import java.security.Provider;

public final class OpenSSLFIPSProvider extends Provider {

	/*
	 * FIPS Validation Certificate #1747
	 * http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm#1747
	 * 
	 * OpenSSL FIPS Object Module (Software Version: 2.0, 2.0.1, 2.0.2, 2.0.3,
	 * 2.0.4 or 2.0.5)
	 * 
	 * Noted caveats:
	 * 
	 * When built, installed, protected and initialized as assumed by the Crypto
	 * Officer role and as specified in the provided Security Policy.
	 * 
	 * Appendix A of the provided Security Policy specifies the actual
	 * distribution tar file containing the source code of this module.
	 * 
	 * There shall be no additions, deletions or alterations to the tar file
	 * contents as used during module build.
	 * 
	 * The distribution tar file shall be verified as specified in Appendix A of
	 * the provided Security Policy.
	 * 
	 * Installation and protection shall be completed as specified in Appendix A
	 * of the provided Security Policy.
	 * 
	 * Initialization shall be invoked as per Section 4 of the provided Security
	 * Policy.
	 * 
	 * Any deviation from specified verification, protection, installation and
	 * initialization procedures will result in a non FIPS 140-2 compliant
	 * module.
	 * 
	 * Validated to FIPS 140-2
	 * 
	 * Security Policy
	 * 
	 * http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140sp/140sp1747.pdf
	 * 
	 * Consolidated Validation Certificate
	 * 
	 * http://csrc.nist.gov/groups/STM/cmvp/validation.html#05
	 * 
	 * Module build for Android
	 * 
	 * http://wiki.openssl.org/index.php/FIPS_Library_and_Android
	 */

	/**
	 * 
	 */
	private static final long serialVersionUID = -959090391556527224L;

	private native static void initProvider();

	public native String getOpenSSLVersion();

	public native String getOpenSSLCFlags();

	public native String getOpenSSLBuiltOn();

	public native String getOpenSSLPlatform();

	public native String getOpenSSLDir();

	public native void getOpenSSLFIPSSig(byte[] buf);

	public native void getOpenSSLFIPSIncoreSig(byte[] buf);

	static {
		try {
			System.loadLibrary("OpensslFipsProvider");
		} catch (UnsatisfiedLinkError e) {
			System.err.println("Native OpensslFipsProvider library failed to load.\n" + e);
		}
	}

	public OpenSSLFIPSProvider() {
		super(
				"OpenSSLFIPSProvider",
				1.0,
				"OpenSSL FIPS Provider 1.0, implements SecureRandom/SHA-1/SHA-224/SHA-256/SHA-384/SHA-512");

		initProvider();

		/*
		 * SecureRandom based on the OpenSSL Default
		 */
		put("SecureRandom.NativePRNG", "org.keysupport.provider.SecureRandom");
		put("SecureRandom.SHA1PRNG", "org.keysupport.provider.SecureRandom");
		/*
		 * SHA-1
		 */
		put("MessageDigest.SHA-1", "org.keysupport.provider.SHA$SHA1");
		put("Alg.Alias.MessageDigest.SHA", "SHA-1");
		put("Alg.Alias.MessageDigest.SHA1", "SHA-1");
		/*
		 * SHA-224
		 */
		put("MessageDigest.SHA224", "org.keysupport.provider.SHA$SHA224");
		put("Alg.Alias.MessageDigest.SHA-224", "SHA224");
		/*
		 * SHA-256
		 */
		put("MessageDigest.SHA256", "org.keysupport.provider.SHA$SHA256");
		put("Alg.Alias.MessageDigest.SHA-256", "SHA256");
		/*
		 * SHA-384
		 */
		put("MessageDigest.SHA384", "org.keysupport.provider.SHA$SHA384");
		put("Alg.Alias.MessageDigest.SHA-384", "SHA384");
		/*
		 * SHA-512
		 */
		put("MessageDigest.SHA512", "org.keysupport.provider.SHA$SHA512");
		put("Alg.Alias.MessageDigest.SHA-512", "SHA512");
		/*
		 * RSA Signatures - PKCS#1 v1.5
		 */
		put("Signature.SHA1withRSA",
				"org.keysupport.provider.RSASignature$SHA1withRSA");
		put("Signature.SHA224withRSA",
				"org.keysupport.provider.RSASignature$SHA224withRSA");
		put("Signature.SHA256withRSA",
				"org.keysupport.provider.RSASignature$SHA256withRSA");
		put("Signature.SHA384withRSA",
				"org.keysupport.provider.RSASignature$SHA384withRSA");
		put("Signature.SHA512withRSA",
				"org.keysupport.provider.RSASignature$SHA512withRSA");
		/*
		 * RSA Signatures - PSS
		 */
		put("Signature.SHA1withRSAandMGF1",
				"org.keysupport.provider.RSASignature$SHA1withRSAandMGF1");
		put("Signature.SHA224withRSAandMGF1",
				"org.keysupport.provider.RSASignature$SHA224withRSAandMGF1");
		put("Signature.SHA256withRSAandMGF1",
				"org.keysupport.provider.RSASignature$SHA256withRSAandMGF1");
		put("Signature.SHA384withRSAandMGF1",
				"org.keysupport.provider.RSASignature$SHA384withRSAandMGF1");
		put("Signature.SHA512withRSAandMGF1",
				"org.keysupport.provider.RSASignature$SHA512withRSAandMGF1");
		/*
		 * RSA Signature Aliases
		 */
		put("Alg.Alias.Signature.1.2.840.113549.1.1.5", "SHA1withRSA");
		put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.5", "SHA1withRSA");
		put("Alg.Alias.Signature.1.3.14.3.2.29", "SHA1withRSA");
		put("Alg.Alias.Signature.1.2.840.113549.1.1.14", "SHA224withRSA");
		put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.14", "SHA224withRSA");
		put("Alg.Alias.Signature.1.2.840.113549.1.1.11", "SHA256withRSA");
		put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.11", "SHA256withRSA");
		put("Alg.Alias.Signature.1.2.840.113549.1.1.12", "SHA384withRSA");
		put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.12", "SHA384withRSA");
		put("Alg.Alias.Signature.1.2.840.113549.1.1.13", "SHA512withRSA");
		put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.13", "SHA512withRSA");

		/*
		 * ECDSA Signatures
		 */
		put("Signature.SHA256withECDSA",
				"org.keysupport.provider.ECDSASignature$SHA256withECDSA");
		put("Signature.SHA384withECDSA",
				"org.keysupport.provider.ECDSASignature$SHA384withECDSA");
		/*
		 * ECDSA Signature Aliases
		 */
		put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.2", "SHA256withECDSA");
		put("Alg.Alias.Signature.1.2.840.10045.4.3.2", "SHA256withECDSA");
		put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.3", "SHA384withECDSA");
		put("Alg.Alias.Signature.1.2.840.10045.4.3.3", "SHA384withECDSA");
		/*
		 * ECDSA Supporting Classes
		 */
		String ecKeyClasses = "java.security.interfaces.ECPublicKey";
		put("Signature.SHA256withECDSA SupportedKeyClasses", ecKeyClasses);
		put("Signature.SHA384withECDSA SupportedKeyClasses", ecKeyClasses);
		/*
		 * Implementation
		 */
		put("SecureRandom.NativePRNG ImplementedIn", "Software");
		put("SecureRandom.SHA1PRNG ImplementedIn", "Software");
		put("MessageDigest.SHA1 ImplementedIn", "Software");
		put("MessageDigest.SHA224 ImplementedIn", "Software");
		put("MessageDigest.SHA256 ImplementedIn", "Software");
		put("MessageDigest.SHA384 ImplementedIn", "Software");
		put("MessageDigest.SHA512 ImplementedIn", "Software");
		put("Signature.SHA1withRSA ImplementedIn", "Software");
		put("Signature.SHA224withRSA ImplementedIn", "Software");
		put("Signature.SHA256withRSA ImplementedIn", "Software");
		put("Signature.SHA384withRSA ImplementedIn", "Software");
		put("Signature.SHA512withRSA ImplementedIn", "Software");
		put("Signature.SHA256withECDSA ImplementedIn", "Software");
		put("Signature.SHA384withECDSA ImplementedIn", "Software");

	}

}
