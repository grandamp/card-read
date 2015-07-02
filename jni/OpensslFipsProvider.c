/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 *
 * $Id: OpensslFipsProvider.c 293 2013-12-19 15:49:22Z tejohnson $
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

#include <android/log.h>
#include <jni.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/fips.h>
#include <string.h>

#include "OpenSSLFipsProvider.h"

typedef struct RSA_Ctx_ {
	RSA *rsa;
} RSA_Ctx;

static int destroy_rsa_ctx(RSA_Ctx *rsa);

typedef struct EC_Ctx_ {
	EC_KEY *ec;
} EC_Ctx;

static int destroy_ec_ctx(EC_Ctx *ec);

/*
 * Initialization and module information
 */
void Java_org_keysupport_provider_OpenSSLFIPSProvider_initProvider(JNIEnv *env,
		jclass clazz) {

	int mode = 0;

	mode = FIPS_mode();

	if (!mode) {
		LOGD("Attempting to enable FIPS mode");
		if (FIPS_mode_set(1)) {
			//OpenSSL_add_all_algorithms();
			LOGD("FIPS mode enabled");
		} else {
			ERR_load_crypto_strings();
			LOGE("Failed to enable FIPS mode");
			LOGE("%s\n", ERR_error_string(ERR_peek_error(), NULL));
			ERR_free_strings();
		}
	}
}

jstring Java_org_keysupport_provider_OpenSSLFIPSProvider_getOpenSSLVersion(
		JNIEnv* env, jobject javaThis) {

	return (*env)->NewStringUTF(env, SSLeay_version(SSLEAY_VERSION));

}

jstring Java_org_keysupport_provider_OpenSSLFIPSProvider_getOpenSSLCFlags(
		JNIEnv* env, jobject javaThis) {

	return (*env)->NewStringUTF(env, SSLeay_version(SSLEAY_CFLAGS));

}

jstring Java_org_keysupport_provider_OpenSSLFIPSProvider_getOpenSSLBuiltOn(
		JNIEnv* env, jobject javaThis) {

	return (*env)->NewStringUTF(env, SSLeay_version(SSLEAY_BUILT_ON));

}

jstring Java_org_keysupport_provider_OpenSSLFIPSProvider_getOpenSSLPlatform(
		JNIEnv* env, jobject javaThis) {

	return (*env)->NewStringUTF(env, SSLeay_version(SSLEAY_PLATFORM));

}

jstring Java_org_keysupport_provider_OpenSSLFIPSProvider_getOpenSSLDir(
		JNIEnv* env, jobject javaThis) {

	return (*env)->NewStringUTF(env, SSLeay_version(SSLEAY_DIR));

}

void Java_org_keysupport_provider_OpenSSLFIPSProvider_getOpenSSLFIPSSig(
		JNIEnv* env, jobject javaThis, jbyteArray buf) {

	(*env)->SetByteArrayRegion(env, buf, 0, 20, FIPS_signature);

}

void Java_org_keysupport_provider_OpenSSLFIPSProvider_getOpenSSLFIPSIncoreSig(
		JNIEnv* env, jobject javaThis, jbyteArray buf) {

	int len = 0;

	len = FIPS_incore_fingerprint(Calculated_signature,
			sizeof(Calculated_signature));

	if (len < 0) {
		LOGE("Failed to calculate expected signature");
	} else {
		(*env)->SetByteArrayRegion(env, buf, 0, 20, Calculated_signature);
	}

}

/*
 * SHA
 */
jlong Java_org_keysupport_provider_SHA_jniInit(JNIEnv *env, jobject obj, jint jmdid) {

//	LOGD("entering SHA_jniInit");

	EVP_MD_CTX *ctx = 0;
	const EVP_MD *md;

	if (!(ctx = (EVP_MD_CTX *) malloc(sizeof(EVP_MD_CTX)))) {
		throw_exception(env, "java/lang/RuntimeException", "allocating EVP_MD_CTX");
		free(ctx);
		return (0);
	}

	md = FIPS_get_digestbynid(jmdid);
	ctx = EVP_MD_CTX_create();
	FIPS_digestinit(ctx, md);

//	LOGD("leaving SHA_jniInit");

	return ((long) ctx);

}

void Java_org_keysupport_provider_SHA_jniEngineUpdate(JNIEnv *env, jobject obj,
		jbyteArray buf, jint off, jint length) {

//	LOGD("entering SHA_jniEngineUpdate");

	EVP_MD_CTX *ctx;
	jbyte buff[length];

	if (!(ctx = get_ptr(env, obj))) {
		return;
	}
	(*env)->GetByteArrayRegion(env, buf, 0, length, buff);
	FIPS_digestupdate(ctx, buff + off, length);

//	LOGD("leaving SHA_jniEngineUpdate");

}

void Java_org_keysupport_provider_SHA_jniEngineDigest(JNIEnv *env, jobject obj,
		jbyteArray buf) {

//	LOGD("entering SHA_jniEngineDigest");

	int result = 0;
	unsigned char md[64];
	EVP_MD_CTX *ctx;
	int md_len = 1;

	if (!(ctx = get_ptr(env, obj))) {
		return;
	}

	result = FIPS_digestfinal(ctx, md, &md_len);
	if (result != 1) {
		LOGE("FIPS_digestfinal Failed ");
	} else {
		(*env)->SetByteArrayRegion(env, buf, 0, md_len, md);
	}

//	LOGD("leaving SHA_jniEngineDigest");

}

void Java_org_keysupport_provider_SHA_jniEngineReset(JNIEnv *env, jobject obj,
		jint jmdid) {

//	LOGD("entering SHA_jniEngineReset");

	Java_org_keysupport_provider_SHA_jniInit(env, obj, jmdid);

//	LOGD("leaving SHA_jniEngineReset");

}

void Java_org_keysupport_provider_SHA_jniDestroy(JNIEnv *env, jobject obj) {

//	LOGD("entering SHA_jniDestroy");

	EVP_MD_CTX *ctx;

	if (!(ctx = get_ptr(env, obj))) {
		return;
	}
	FIPS_md_ctx_destroy(ctx);

//	LOGD("leaving SHA_jniDestroy");

}

/*
 * DRBG
 */
void Java_org_keysupport_provider_SecureRandom_jniFIPSRandBytes(JNIEnv *env,
		jobject obj, jbyteArray jbuf) {

//	LOGD("entering jniFIPSRandBytes");

	jsize len = 0;
	int result = 0;

	len = (*env)->GetArrayLength(env, jbuf);
	unsigned char buf[len];
	result = FIPS_rand_bytes(buf, len);
	if (result != 1) {
		LOGE("OpenSSL Default FIPS DRBG Failed to produce output!");

	} else {
		(*env)->SetByteArrayRegion(env, jbuf, 0, len, buf);
	}

//	LOGD("leaving jniFIPSRandBytes");

}

/*
 * RSA Signature
 */
static int destroy_rsa_ctx(RSA_Ctx *rsa) {

	if (!rsa) {
		return (0);
	}
	if (rsa->rsa) {
		RSA_free(rsa->rsa);
	}
	memset(rsa, 0, sizeof(RSA_Ctx));
	free(rsa);

	return (0);

}

jlong Java_org_keysupport_provider_RSASignature_jniVerifyInit(JNIEnv *env,
		jobject obj, jbyteArray jmod, jbyteArray jpe) {

//	LOGD("entering RSASignature_jniVerifyInit");

	RSA_Ctx *rsa = 0;

	if (!(rsa = (RSA_Ctx *) calloc(sizeof(RSA_Ctx), 1))) {
		throw_exception(env, "java/lang/RuntimeException", "allocating RSA_Ctx");
		destroy_rsa_ctx(rsa);
		return 0;
	}
	if (!(rsa->rsa = RSA_new())) {
		throw_exception(env, "java/lang/RuntimeException", "calling RSA_new()");
		destroy_rsa_ctx(rsa);
		return 0;
	}
	if (!jba_to_bigint(env, &(rsa->rsa->n), jmod)) {
		throw_exception(env, "java/lang/RuntimeException", "setting RSA modulus");
		destroy_rsa_ctx(rsa);
		return 0;
	}
	if (!jba_to_bigint(env, &(rsa->rsa->e), jpe)) {
		throw_exception(env, "java/lang/RuntimeException", "setting RSA public exponent");
		destroy_rsa_ctx(rsa);
		return 0;
	}

//	LOGD("leaving RSASignature_jniVerifyInit");

	return ((long) rsa);

}

jint Java_org_keysupport_provider_RSASignature_jniVerifyFinal(JNIEnv *env,
		jobject obj, jbyteArray jmsg, jint jmdid, jint jpadMode,
		jbyteArray jsig) {

//	LOGD("entering RSASignature_jniVerifyFinal");

	jsize msgLen = 0;
	jsize sigLen = 0;
	RSA_Ctx *rsa;
	EVP_MD_CTX *ctx = 0;
	const EVP_MD *md;
	const EVP_MD *mdMgf;
	int saltLen = 0;

	LOGI("FIPS Mode of operation: %d\n", FIPS_mode());

	if (!(rsa = get_ptr(env, obj))) {
		throw_exception(env,"java/lang/RuntimeException", "obtaining RSA_Ctx");
		return 0;
	}
	if (jpadMode == RSA_PKCS1_PADDING) {
//		LOGD("RSA PKCS#1 v1.5 Padding");
	} else if (jpadMode == RSA_PKCS1_PSS_PADDING) {
//		LOGD("RSA PSS Padding");
		mdMgf = FIPS_get_digestbynid(jmdid);
		saltLen = EVP_MD_size(mdMgf);
	}
	if (!(ctx = (EVP_MD_CTX *) malloc(sizeof(EVP_MD_CTX)))) {
		throw_exception(env, "java/lang/RuntimeException", "allocating EVP_MD_CTX");
		destroy_rsa_ctx(rsa);
		FIPS_md_ctx_destroy(ctx);
		return 0;
	}
	md = FIPS_get_digestbynid(jmdid);
	ctx = EVP_MD_CTX_create();
	msgLen = (*env)->GetArrayLength(env, jmsg);
	sigLen = (*env)->GetArrayLength(env, jsig);
	jbyte msg[msgLen];
	jbyte sig[sigLen];
	(*env)->GetByteArrayRegion(env, jmsg, 0, msgLen, msg);
	(*env)->GetByteArrayRegion(env, jsig, 0, sigLen, sig);
	FIPS_digestinit(ctx, md);
	int ok = FIPS_rsa_verify(rsa->rsa, msg, msgLen, md, jpadMode, saltLen,
			mdMgf, sig, sigLen);
//	LOGD("FIPS_rsa_verify Returned: %d\n", ok);
	FIPS_md_ctx_destroy(ctx);
	if (ok == 0) {
		/*
		 * TODO:  Print any pending errors
		 * ERR_print_errors_fp(ANDROID_LOG_ERROR);
		 */
		ERR_load_crypto_strings();
		LOGE("%s\n", ERR_error_string(ERR_peek_error(), NULL));
		throw_exception(env, "java/security/SignatureException",
				"Bad Signature");
		ERR_free_strings();
		return 0;
	}

//	LOGD("leaving RSASignature_jniVerifyFinal");

	return ok;

}

void Java_org_keysupport_provider_RSASignature_jniDestroy(JNIEnv *env,
		jobject obj) {

//	LOGD("entering RSASignature_jniDestroy");

	RSA_Ctx *rsa;

	if (!(rsa = get_ptr(env, obj))) {
		return;
	}
	destroy_rsa_ctx(rsa);

//	LOGD("leaving RSASignature_jniDestroy");

}

/*
 * ECDSA Signature
 */
static int destroy_ec_ctx(EC_Ctx *ec) {

	if (!ec) {
		return (0);
	}
	if (ec->ec) {
		EC_KEY_free(ec->ec);
	}
	memset(ec, 0, sizeof(EC_Ctx));
	free(ec);

	return (0);

}

jlong Java_org_keysupport_provider_ECDSASignature_jniVerifyInit(JNIEnv *env,
		jobject obj, jint jcid, jbyteArray jx, jbyteArray jy) {

//	LOGD("entering ECDSASignature_jniVerifyInit");

	EC_Ctx *ec = 0;
	BIGNUM *x, *y;

	if (!(ec = (EC_Ctx *) calloc(sizeof(EC_Ctx), 1))) {
		throw_exception(env, "java/lang/RuntimeException", "allocating EC_Ctx");
		destroy_ec_ctx(ec);
		return 0;
	}
	if (!(ec->ec = EC_KEY_new_by_curve_name(jcid))) {
		throw_exception(env, "java/lang/RuntimeException", "allocating EC_KEY");
		destroy_ec_ctx(ec);
		return 0;
	}
	if (!jba_to_bigint(env, &x, jx)) {
		throw_exception(env, "java/lang/RuntimeException", "importing affine coordinate x");
		destroy_ec_ctx(ec);
		return 0;
	}
	if (!jba_to_bigint(env, &y, jy)) {
		throw_exception(env, "java/lang/RuntimeException", "importing affine coordinate y");
		destroy_ec_ctx(ec);
		return 0;
	}
	if (!(EC_KEY_set_public_key_affine_coordinates(ec->ec, x, y))) {
		LOGE("Failed to set EC_KEY affine coordinates");
		throw_exception(env, "java/lang/RuntimeException", "setting EC_KEY affine coordinates");
		destroy_ec_ctx(ec);
		return 0;
	}

//	LOGD("leaving ECDSASignature_jniVerifyInit");

	return ((long) ec);

}

jint Java_org_keysupport_provider_ECDSASignature_jniVerifyFinal(JNIEnv *env,
		jobject obj, jbyteArray jmsg, jint jmdid, jbyteArray jsig) {

//	LOGD("entering ECDSASignature_jniVerifyFinal");

	EC_Ctx *ec;
	EVP_MD_CTX *ctx = 0;
	const EVP_MD *md;
	jsize msgLen = 0;
	jsize sigLen = 0;
	const unsigned char *sig_ptr = NULL;

	if (!(ec = get_ptr(env, obj))) {
		LOGE("Failed to obtain key pointer");
		return 0;
	}
	if (!(ctx = (EVP_MD_CTX *) malloc(sizeof(EVP_MD_CTX)))) {
		throw_exception(env, "java/lang/RuntimeException",
				"allocating EVP_MD_CTX");
		destroy_ec_ctx(ec);
		FIPS_md_ctx_destroy(ctx);
		return 0;
	}
	md = FIPS_get_digestbynid(jmdid);
	ctx = EVP_MD_CTX_create();
	msgLen = (*env)->GetArrayLength(env, jmsg);
	sigLen = (*env)->GetArrayLength(env, jsig);
	jbyte msg[msgLen];
	jbyte sig[sigLen];
	(*env)->GetByteArrayRegion(env, jmsg, 0, msgLen, msg);
	(*env)->GetByteArrayRegion(env, jsig, 0, sigLen, sig);
	sig_ptr = sig;
	ECDSA_SIG *esig = d2i_ECDSA_SIG(NULL, &sig_ptr, sigLen);
	FIPS_digestinit(ctx, md);
	int ok = FIPS_ecdsa_verify(ec->ec, msg, msgLen, md, esig);
	/*
	 * This is handled a bit differently than the way OpenSSL
	 * handles RSA Signatures, so our error handling below is a bit different.
	 *
	 *  returns
	 *      1: correct signature
	 *      0: incorrect signature
	 *     -1: error
	 */
//	LOGD("FIPS_ecdsa_verify Returned: %d\n", ok);
	FIPS_md_ctx_destroy(ctx);
	FIPS_ecdsa_sig_free(esig);
	if (ok == 0) {
		throw_exception(env, "java/security/SignatureException",
				"Bad Signature");
		return 0;
	} else if (ok == -1) {
		/*
		 * TODO:  Print any pending errors
		 * ERR_print_errors_fp(ANDROID_LOG_ERROR);
		 */
		ERR_load_crypto_strings();
		LOGE("%s", ERR_error_string(ERR_peek_error(), NULL));
		throw_exception(env, "java/security/SignatureException",
				"jniVerifyFinal fail");
		ERR_free_strings();
		return 0;
	}

//	LOGD("leaving ECDSASignature_jniVerifyFinal");

	return ok;

}

void Java_org_keysupport_provider_ECDSASignature_jniDestroy(JNIEnv *env,
		jobject obj) {

//	LOGD("entering ECDSASignature_jniDestroy");

	EC_Ctx *ec;

	if (!(ec = get_ptr(env, obj))) {
		return;
	}

	destroy_ec_ctx(ec);

//	LOGD("leaving ECDSASignature_jniDestroy");
}

/*
 * Common
 */

void *get_ptr(JNIEnv *env, jobject obj) {

	jclass clazz;
	jfieldID fid;
	jlong val;

	clazz = (*env)->GetObjectClass(env, obj);
	fid = (*env)->GetFieldID(env, clazz, "_ptr", "J");
	val = (*env)->GetLongField(env, obj, fid);

	if (!val) {
		throw_exception(env, "java/lang/RuntimeException",
				"Context not found");
		return (0);
	}

	return ((void *) (intptr_t) val);

}

void throw_exception(JNIEnv *env, char *except_type, char *msg) {

	jclass clazz;
	clazz = (*env)->FindClass(env, except_type);
	(*env)->ThrowNew(env, clazz, msg);

}

int jba_to_bigint(JNIEnv *env, BIGNUM **out, jbyteArray jba) {

	jsize len;

	len = (*env)->GetArrayLength(env, jba);
	if (!len) {
		throw_exception(env, "java/lang/RuntimeException", "Could not convert BIGNUM");
		return (0);
	}
//	LOGD("BigInt Size is: %d\n", len);
	jbyte buff[len];
	(*env)->GetByteArrayRegion(env, jba, 0, len, buff);
	*out = BN_bin2bn(buff, len, NULL);
	if (*out == NULL) {
		throw_exception(env, "java/lang/RuntimeException", "Could not convert BIGNUM");
		return (0);
	}

	return (1);

}

