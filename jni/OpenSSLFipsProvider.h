/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 *
 * $Id: OpenSSLFipsProvider.h 293 2013-12-19 15:49:22Z tejohnson $
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

#include <openssl/ssl.h>

#define LOG_TAG "libOpenSSLFIPSProvider"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern unsigned char FIPS_signature[20];
static unsigned char Calculated_signature[20];
extern unsigned int FIPS_incore_fingerprint(unsigned char *, unsigned int);

void *get_ptr(JNIEnv *env, jobject thisObj);
void throw_exception(JNIEnv *env, char *except_type, char *msg);
