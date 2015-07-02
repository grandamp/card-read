/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: RSASignature.java 293 2013-12-19 15:49:22Z tejohnson $
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

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.RSAPublicKey;

/**
 * Uses:
 * 
 * FIPS_rsa_verify in file ./fips/rsa/fips_rsa_sign.[o|c]
 * 
 * int FIPS_rsa_verify( struct rsa_st *rsa, const unsigned char *msg, int
 * msglen, const struct env_md_st *mhash, int rsa_pad_mode, int saltlen, const
 * struct env_md_st *mgf1Hash, const unsigned char *sigbuf, unsigned int siglen)
 * 
 * <-> rsa -> msg -> msglen -> mhash -> rsa_pad_mode -> saltlen -> mgf1Hash ->
 * sigbuf -> siglen <- Return
 * 
 * In the case of PSS/MGF1, the mgf1Hash and mhash are the same. saltlen is not
 * needed since we can simply get it from EVP_MD_size(EVP_MD) This means the
 * other variables can be eliminated and we only need to set rsa_pad_mode to
 * either:
 * 
 * - RSA_PKCS1_PADDING -or- - RSA_PKCS1_PSS_PADDING
 * 
 * @author tejohnson
 * 
 */
public abstract class RSASignature extends SignatureSpi {

	/*
	 * #define RSA_PKCS1_PADDING 1
	 */
	final static int RSA_PKCS1_PADDING = 1;
	/*
	 * #define RSA_SSLV23_PADDING 2
	 */
	final static int RSA_SSLV23_PADDING = 2;
	/*
	 * #define RSA_NO_PADDING 3
	 */
	final static int RSA_NO_PADDING = 3;
	/*
	 * #define RSA_PKCS1_OAEP_PADDING 4
	 */
	final static int RSA_PKCS1_OAEP_PADDING = 4;
	/*
	 * #define RSA_X931_PADDING 5
	 */
	final static int RSA_X931_PADDING = 5;
	/*
	 * #define RSA_PKCS1_PSS_PADDING 6
	 */
	final static int RSA_PKCS1_PSS_PADDING = 6;

	long _ptr = 0;
	private RSAPublicKey pKey = null;
	private ByteArrayOutputStream msg = null;
	private int mdId = 0;
	private int padMode = 0;
	private byte[] sig = null;

	/*
	 * Java_org_keysupport_provider_RSASignature_jniVerifyInit(JNIEnv *env,
	 * jobject obj, jbyteArray jmod, jbyteArray jpe)
	 */
	private native long jniVerifyInit(byte[] mod, byte[] pe);

	/*
	 * Java_org_keysupport_provider_RSASignature_jniVerifyFinal(JNIEnv *env,
	 * jobject obj, jbyteArray jmsg, jint jmdid, jint jpadMode, jbyteArray
	 * jsig)
	 */
	private native int jniVerifyFinal(byte[] msg, int mdId, int padMode,
			byte[] sig);

	/*
	 * Java_org_keysupport_provider_RSASignature_jniDestroy(JNIEnv *env, jobject obj)
	 */
	private native void jniDestroy();

	/**
	 * 
	 */
	public RSASignature() {

	}

	/**
	 * 
	 */
	RSASignature(int algorithm, int padmode) {
		this.mdId = algorithm;
		this.padMode = padmode;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.security.SignatureSpi#engineGetParameter(java.lang.String)
	 */
	@Override
	protected Object engineGetParameter(String param)
			throws InvalidParameterException {
		return null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.security.SignatureSpi#engineInitSign(java.security.PrivateKey)
	 */
	@Override
	protected void engineInitSign(PrivateKey privateKey)
			throws InvalidKeyException {

		throw new InvalidKeyException("Signing not implemented yet");

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.security.SignatureSpi#engineInitVerify(java.security.PublicKey)
	 */
	@Override
	protected void engineInitVerify(PublicKey publicKey)
			throws InvalidKeyException {

		if (!(publicKey instanceof RSAPublicKey)) {
			throw new InvalidKeyException("Not an RSA Public Key");
		}

		this.pKey = (RSAPublicKey) publicKey;

		byte[] mod = this.pKey.getModulus().toByteArray();

		_ptr = jniVerifyInit(mod, this.pKey.getPublicExponent().toByteArray());
		this.msg = new ByteArrayOutputStream();

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.security.SignatureSpi#engineSetParameter(java.lang.String,
	 * java.lang.Object)
	 */
	@Override
	protected void engineSetParameter(String param, Object value)
			throws InvalidParameterException {
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.security.SignatureSpi#engineSign()
	 */
	@Override
	protected byte[] engineSign() throws SignatureException {

		return null;

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.security.SignatureSpi#engineUpdate(byte)
	 */
	@Override
	protected void engineUpdate(byte b) throws SignatureException {

		this.msg.write(b);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.security.SignatureSpi#engineUpdate(byte[], int, int)
	 */
	@Override
	protected void engineUpdate(byte[] b, int off, int len)
			throws SignatureException {

		this.msg.write(b, off, len);

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.security.SignatureSpi#engineVerify(byte[])
	 */
	@Override
	protected boolean engineVerify(byte[] sigBytes) throws SignatureException {

		this.sig = sigBytes;

		/*
		 * Do basic checks then call native method
		 */

		int result = jniVerifyFinal(this.msg.toByteArray(), this.mdId,
				this.padMode, this.sig);

		if (result == 1) {
			return true;
		} else {
			return false;
		}

	}

	@Override
	protected void finalize() {
		jniDestroy();
	}

	/*
	 * PKCS#1 v1.5
	 */
	public static final class SHA1withRSA extends RSASignature {
		public SHA1withRSA() {
			super(SHA.DIGEST_SHA1, RSASignature.RSA_PKCS1_PADDING);
		}
	}

	public static final class SHA224withRSA extends RSASignature {
		public SHA224withRSA() {
			super(SHA.DIGEST_SHA224, RSASignature.RSA_PKCS1_PADDING);
		}
	}

	public static final class SHA256withRSA extends RSASignature {
		public SHA256withRSA() {
			super(SHA.DIGEST_SHA256, RSASignature.RSA_PKCS1_PADDING);
		}
	}

	public static final class SHA384withRSA extends RSASignature {
		public SHA384withRSA() {
			super(SHA.DIGEST_SHA384, RSASignature.RSA_PKCS1_PADDING);
		}
	}

	public static final class SHA512withRSA extends RSASignature {
		public SHA512withRSA() {
			super(SHA.DIGEST_SHA512, RSASignature.RSA_PKCS1_PADDING);
		}
	}

	/*
	 * RSA PSS
	 */
	public static final class SHA1withRSAandMGF1 extends RSASignature {
		public SHA1withRSAandMGF1() {
			super(SHA.DIGEST_SHA1, RSASignature.RSA_PKCS1_PSS_PADDING);
		}
	}

	public static final class SHA224withRSAandMGF1 extends RSASignature {
		public SHA224withRSAandMGF1() {
			super(SHA.DIGEST_SHA224, RSASignature.RSA_PKCS1_PSS_PADDING);
		}
	}

	public static final class SHA256withRSAandMGF1 extends RSASignature {
		public SHA256withRSAandMGF1() {
			super(SHA.DIGEST_SHA256, RSASignature.RSA_PKCS1_PSS_PADDING);
		}
	}

	public static final class SHA384withRSAandMGF1 extends RSASignature {
		public SHA384withRSAandMGF1() {
			super(SHA.DIGEST_SHA384, RSASignature.RSA_PKCS1_PSS_PADDING);
		}
	}

	public static final class SHA512withRSAandMGF1 extends RSASignature {
		public SHA512withRSAandMGF1() {
			super(SHA.DIGEST_SHA512, RSASignature.RSA_PKCS1_PSS_PADDING);
		}
	}

}
