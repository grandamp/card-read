/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: SHA.java 293 2013-12-19 15:49:22Z tejohnson $
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

import java.security.MessageDigestSpi;

abstract class SHA extends MessageDigestSpi {

	/*
	 * #define NID_sha1 64
	 */
	final static int DIGEST_SHA1 = 64;
	/*
	 * #define NID_sha224 675
	 */
	final static int DIGEST_SHA224 = 675;
	/*
	 * #define NID_sha256 672
	 */
	final static int DIGEST_SHA256 = 672;
	/*
	 * #define NID_sha384 673
	 */
	final static int DIGEST_SHA384 = 673;
	/*
	 * #define NID_sha512 674
	 */
	final static int DIGEST_SHA512 = 674;
	
	int mdId;
	long _ptr = 0;
	int BUFSIZ = 512;
	byte[] buffer = new byte[BUFSIZ];
	int offset = 0;
	int COPYMAX = 16;

	public SHA(int mdId) {
		this.mdId = mdId;
		_ptr = jniInit(this.mdId);
	}

	native long jniInit(int mdId);

	native void jniEngineUpdate(byte[] buf, int offset, int len);

	native void jniEngineDigest(byte[] buf);

	native void jniEngineReset(int mdId);

	native void jniDestroy();

	abstract int mdSize();

	@Override
	protected void engineUpdate(byte x) {
		buffer[offset++] = x;
		if (offset == BUFSIZ)
			jniEngineUpdate(buffer, 0, BUFSIZ);
		offset = 0;
	}

	@Override
	protected void engineUpdate(byte[] in, int off, int len) {
		if (len > COPYMAX || (len + offset >= BUFSIZ)) {
			if (offset > 0)
				jniEngineUpdate(buffer, 0, offset);
			if (len > 0)
				jniEngineUpdate(in, off, len);
			offset = 0;
		} else {
			System.arraycopy(in, off, buffer, offset, len);
			offset += len;
		}
	}

	@Override
	protected byte[] engineDigest() {
		byte[] md = new byte[mdSize()];

		if (offset > 0) {
			jniEngineUpdate(buffer, 0, offset);
			offset = 0;
		}
		jniEngineDigest(md);
		return md;
	}

	@Override
	protected void engineReset() {
		jniEngineReset(this.mdId);
	}

	@Override
	protected void finalize() {
		jniDestroy();
	}

	/*
	 * SHA/SHA1/SHA-1
	 */
	public static final class SHA1 extends SHA {

		public SHA1() {
			super(SHA.DIGEST_SHA1);
		}

		@Override
		public int mdSize() {
			return 20;
		}

	}

	/*
	 * SHA224/SHA-224
	 */
	public static final class SHA224 extends SHA {

		public SHA224() {
			super(SHA.DIGEST_SHA224);
		}

		@Override
		public int mdSize() {
			return 28;
		}

	}

	/*
	 * SHA256/SHA-256
	 */
	public static final class SHA256 extends SHA {

		public SHA256() {
			super(SHA.DIGEST_SHA256);
		}

		@Override
		public int mdSize() {
			return 32;
		}

	}

	/*
	 * SHA384/SHA-384
	 */
	public static final class SHA384 extends SHA {

		public SHA384() {
			super(SHA.DIGEST_SHA384);
		}

		@Override
		public int mdSize() {
			return 48;
		}

	}

	/*
	 * SHA512/SHA-512
	 */
	public static final class SHA512 extends SHA {

		public SHA512() {
			super(SHA.DIGEST_SHA512);
		}

		@Override
		public int mdSize() {
			return 64;
		}

	}

}
