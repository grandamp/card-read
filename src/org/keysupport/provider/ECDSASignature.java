/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: ECDSASignature.java 299 2013-12-23 00:40:06Z tejohnson $
 * 
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 299 $ 
 * 
 * Changed: $LastChangedDate: 2013-12-22 19:40:06 -0500 (Sun, 22 Dec 2013) $
 *****************************************************************************/

package org.keysupport.provider;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.ECPublicKey;

/**
 * 
 * Uses:
 * 
 * FIPS_ecdsa_verify in file ./fips/ecdsa/fips_ecdsa_sign.[o|c] int
 * 
 * FIPS_ecdsa_verify(EC_KEY *key, const unsigned char *msg, size_t msglen, const
 * EVP_MD *mhash, ECDSA_SIG *s)
 * 
 * <-> key -> msg -> msglen -> mhash <-> s <-Return
 * 
 * 
 * @author tejohnson
 * 
 */
public class ECDSASignature extends SignatureSpi {
	
	/*
	 * #define NID_X9_62_prime256v1 415
	 */
	final static int CURVE_P256 = 415;
	/*
	 * #define NID_secp384r1 715
	 */
	final static int CURVE_P384 = 715;
	
	long _ptr = 0;
	private ECPublicKey pKey = null;
	private ByteArrayOutputStream msg = null;
	private int mdId = 0;
	private byte[] sig = null;

	/*
	 * Java_org_keysupport_provider_ECDSASignature_jniVerifyInit(JNIEnv *env,
	 * jobject obj, jstring jcName, jbyteArray jx, jbyteArray jy)
	 */
	private native long jniVerifyInit(int cid, byte[] x, byte[] y);

	/*
	 * Java_org_keysupport_provider_ECDSASignature_jniVerifyFinal(JNIEnv *env,
	 * jobject obj, jbyteArray jmsg, jstring jmdName, jbyteArray jsig)
	 */
	private native int jniVerifyFinal(byte[] msg, int mdId, byte[] sig);

	/*
	 * Java_org_keysupport_provider_RSASignature_jniDestroy(JNIEnv *env, jobject obj)
	 */
	private native void jniDestroy();

	/**
	 * 
	 */
	public ECDSASignature() {

	}

	/**
	 * 
	 */
	ECDSASignature(int algorithm) {
		this.mdId = algorithm;
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

		int cId = 0;

		if (!(publicKey instanceof ECPublicKey)) {
			throw new InvalidKeyException("Not an EC Public Key!");
		}

		this.pKey = (ECPublicKey) publicKey;

		if (this.mdId == SHA.DIGEST_SHA256) {
			cId = ECDSASignature.CURVE_P256;
		} else if (this.mdId == SHA.DIGEST_SHA384) {
			cId = ECDSASignature.CURVE_P384;
		} else {
			throw new InvalidKeyException(
					"Unsupported Curve!  This implementation only supports P-256 (with SHA-256) and P-384 (with SHA-384)");
		}

		try {
			_ptr = jniVerifyInit(cId,
					this.pKey.getW().getAffineX().toByteArray(), this.pKey.getW()
					.getAffineY().toByteArray());
		} catch(RuntimeException e) {
			throw new InvalidKeyException(e.getLocalizedMessage());
		}
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

		int result = jniVerifyFinal(this.msg.toByteArray(), this.mdId, this.sig);

		if (result == 1) {
			return true;
		} else {
			return false;
		}

	}

	@Override
	protected void finalize() {
		try {
			jniDestroy();
		} catch(RuntimeException e) {
			/*
			 * TODO:  For now, just ignore, but a runtime exception will occur if the
			 * context does not exist
			 */
			
		}

	}

	public static final class SHA256withECDSA extends ECDSASignature {
		public SHA256withECDSA() {
			super(SHA.DIGEST_SHA256);
		}
	}

	public static final class SHA384withECDSA extends ECDSASignature {
		public SHA384withECDSA() {
			super(SHA.DIGEST_SHA384);
		}
	}

}
