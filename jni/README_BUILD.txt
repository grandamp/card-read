
http://wiki.openssl.org/index.php/FIPS_Library_and_Android

Environment:


export ANDROID_API=android-14
export PREBUILT_FIPS_OPENSSL=/usr/local/ssl/$ANDROID_API
export ANDROID_NDK_ROOT=/usr/local/src/development/ndk/android-ndk-r9b
export ANDROID_EABI=arm-linux-androideabi-4.6
export ANDROID_SYSROOT="$ANDROID_NDK_ROOT/platforms/android-14/arch-arm"
export ANDROID_TOOLCHAIN="$ANDROID_NDK_ROOT/toolchains/arm-linux-androideabi-4.6/prebuilt/linux-x86_64/bin"
export FIPS_SIG=/usr/local/ssl/android-14/bin/incore
export CROSS_COMPILE=arm-linux-androideabi-
export ANDROID_DEV="$ANDROID_NDK_ROOT/platforms/android-14/arch-arm/usr"
export CC=`find /usr/local/ssl/$ANDROID_API -name fipsld`
export FIPSLD_CC="$ANDROID_TOOLCHAIN/arm-linux-androideabi-gcc"

$CC --sysroot="$ANDROID_SYSROOT" OpensslFipsProvider.c -fPIC -shared -I/usr/local/ssl/android-14/include -I/usr/local/src/development/ndk/android-ndk-r9b/platforms/android-14/arch-arm/usr/include -Wl,-Bstatic -lcrypto -lssl -L/usr/local/ssl/android-14/lib -L/usr/local/src/development/ndk/android-ndk-r9b/platforms/android-14/arch-arm/usr/lib -o libOpensslFipsProvider.so -Wl,-Bdynamic -llog


Updating OpenSSL Build using special build server.  This document will be replaced with a more detailed document in the near future.

Updated build variables:

export ANDROID_API=android-18
export PREBUILT_FIPS_OPENSSL=/usr/local/build/ssl/32/$ANDROID_API
export ANDROID_NDK_ROOT=/usr/local/build/AndroidNDK/android-ndk32-r10b
export ANDROID_EABI=arm-linux-androideabi-4.8
export ANDROID_SYSROOT="$ANDROID_NDK_ROOT/platforms/$ANDROID_API/arch-arm"
export ANDROID_TOOLCHAIN="$ANDROID_NDK_ROOT/toolchains/$ANDROID_EABI/prebuilt/linux-x86_64/bin"
export FIPS_SIG=/usr/local/build/ssl/32/android-18/bin/incore
export CROSS_COMPILE=arm-linux-androideabi-
export ANDROID_DEV="$ANDROID_NDK_ROOT/platforms/$ANDROID_API/arch-arm/usr"
export CC="$PREBUILT_FIPS_OPENSSL/bin/fipsld"
export FIPSLD_CC="$ANDROID_TOOLCHAIN/arm-linux-androideabi-gcc"

$CC --sysroot="$ANDROID_SYSROOT" OpensslFipsProvider.c -fPIC -shared -I$PREBUILT_FIPS_OPENSSL/include -I$ANDROID_DEV/include -Wl,-Bstatic -lcrypto -lssl -L$PREBUILT_FIPS_OPENSSL/lib -L$ANDROID_DEV/lib -o libOpensslFipsProvider.so -Wl,-Bdynamic -llog

Output:  2da493f76f3f9543a28cc330778dc4ff5e3b30b1e99a8a2630cf71063645c30a  libOpensslFipsProvider.so

Information:

OpenSSL FIPS Module Version:  2.0.8
OpenSSL FIPS Capable Version: 1.0.1i

Updating again, because I should have built using the min version of our app, which is android-16, not android-18.
Further, only the 32-bit version will be built, as it will be compatible with the 64-bit processor, just not optimized.
We will need to wait for another FIPS validated version of the OpenSSL Module that can be built using the 64-bit toolset.
Ultimately, when that occurs, then it may be a bit more complex for our app since we will need to detect 32 or 64 bit platform before loading the native libs.

Update:

export ANDROID_API=android-16
export PREBUILT_FIPS_OPENSSL=/usr/local/build/ssl/$ANDROID_API
export ANDROID_NDK_ROOT=/usr/local/build/AndroidNDK/android-ndk32-r10b
export ANDROID_EABI=arm-linux-androideabi-4.8
export ANDROID_SYSROOT="$ANDROID_NDK_ROOT/platforms/$ANDROID_API/arch-arm"
export ANDROID_TOOLCHAIN="$ANDROID_NDK_ROOT/toolchains/$ANDROID_EABI/prebuilt/linux-x86_64/bin"
export FIPS_SIG=$PREBUILT_FIPS_OPENSSL/bin/incore
export CROSS_COMPILE=arm-linux-androideabi-
export ANDROID_DEV="$ANDROID_NDK_ROOT/platforms/$ANDROID_API/arch-arm/usr"
export CC="$PREBUILT_FIPS_OPENSSL/bin/fipsld"
export FIPSLD_CC="$ANDROID_TOOLCHAIN/arm-linux-androideabi-gcc"

$CC --sysroot="$ANDROID_SYSROOT" OpensslFipsProvider.c -fPIC -shared -I$PREBUILT_FIPS_OPENSSL/include -I$ANDROID_DEV/include -Wl,-Bstatic -lcrypto -lssl -L$PREBUILT_FIPS_OPENSSL/lib -L$ANDROID_DEV/lib -o libOpensslFipsProvider.so -Wl,-Bdynamic -llog


