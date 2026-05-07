/**
 * NightOwl — Focused SSL Pinning Bypass
 * Bypasses all known SSL pinning implementations on Android
 *
 * Usage:
 *   frida -H 127.0.0.1:27042 -f com.example.app -l ssl-bypass.js --no-pause
 *   frida -U -f com.example.app -l ssl-bypass.js --no-pause
 */

'use strict';

const TAG = '[NightOwl-SSL]';
let bypassed = 0;

function log(msg)  { console.log(`${TAG} [+] ${msg}`); }
function warn(msg) { console.log(`${TAG} [!] ${msg}`); }

// ─── 1. OkHttp3 CertificatePinner ───────────────────────────────────────────
function bypassOkHttp3() {
    try {
        const CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname) {
            warn(`OkHttp3 CertificatePinner.check bypassed for: ${hostname}`);
        };
        log('OkHttp3 CertificatePinner bypassed');
        bypassed++;
    } catch (_) {}

    try {
        const CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner['check$okhttp'].implementation = function (hostname) {
            warn(`OkHttp3 check$okhttp bypassed for: ${hostname}`);
        };
        log('OkHttp3 check$okhttp bypassed');
        bypassed++;
    } catch (_) {}
}

// ─── 2. TrustManagerImpl (Android system) ────────────────────────────────────
function bypassTrustManagerImpl() {
    try {
        const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain) {
            warn('TrustManagerImpl.verifyChain bypassed');
            return untrustedChain;
        };
        log('TrustManagerImpl bypassed');
        bypassed++;
    } catch (_) {}
}

// ─── 3. X509TrustManager (trust-all) ────────────────────────────────────────
function bypassX509TrustManager() {
    try {
        const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        const SSLContext = Java.use('javax.net.ssl.SSLContext');

        const TrustAll = Java.implement(X509TrustManager, {
            checkClientTrusted: function () {},
            checkServerTrusted: function () {
                warn('X509TrustManager.checkServerTrusted bypassed');
            },
            getAcceptedIssuers: function () { return []; }
        });

        const ctx = SSLContext.getInstance('TLS');
        ctx.init(null, [TrustAll], null);

        SSLContext.getDefault.implementation = function () {
            return ctx;
        };
        log('X509TrustManager bypassed (trust-all)');
        bypassed++;
    } catch (_) {}
}

// ─── 4. WebViewClient SSL errors ─────────────────────────────────────────────
function bypassWebViewSSL() {
    try {
        const WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function (view, handler) {
            warn('WebViewClient.onReceivedSslError bypassed');
            handler.proceed();
        };
        log('WebViewClient SSL error bypassed');
        bypassed++;
    } catch (_) {}
}

// ─── 5. HostnameVerifier ─────────────────────────────────────────────────────
function bypassHostnameVerifier() {
    try {
        const HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        const HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');

        const AllowAll = Java.implement(HostnameVerifier, {
            verify: function () {
                warn('HostnameVerifier.verify bypassed');
                return true;
            }
        });

        HttpsURLConnection.setDefaultHostnameVerifier(AllowAll);
        log('HostnameVerifier bypassed (allow-all)');
        bypassed++;
    } catch (_) {}
}

// ─── 6. Network Security Config (Android 7+) ────────────────────────────────
function bypassNetworkSecurityConfig() {
    try {
        const NetworkSecurityPolicy = Java.use('android.security.net.config.NetworkSecurityConfig');
        NetworkSecurityPolicy.isCleartextTrafficPermitted.implementation = function () {
            return true;
        };
        log('NetworkSecurityConfig cleartext permitted');
        bypassed++;
    } catch (_) {}
}

// ─── 7. TrustKit (popular library) ──────────────────────────────────────────
function bypassTrustKit() {
    try {
        const TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        TrustKit.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function () {
            warn('TrustKit verify bypassed');
            return true;
        };
        log('TrustKit bypassed');
        bypassed++;
    } catch (_) {}
}

// ─── 8. Appcelerator Titanium ────────────────────────────────────────────────
function bypassAppcelerator() {
    try {
        const PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');
        PinningTrustManager.checkServerTrusted.implementation = function () {
            warn('Appcelerator PinningTrustManager bypassed');
        };
        log('Appcelerator bypassed');
        bypassed++;
    } catch (_) {}
}

// ─── 9. PhoneGap / Cordova ──────────────────────────────────────────────────
function bypassCordova() {
    try {
        const CordovaWebViewClient = Java.use('org.apache.cordova.CordovaWebViewClient');
        CordovaWebViewClient.onReceivedSslError.implementation = function (view, handler) {
            warn('Cordova onReceivedSslError bypassed');
            handler.proceed();
        };
        log('Cordova SSL bypassed');
        bypassed++;
    } catch (_) {}
}

// ─── 10. Flutter / Dart (BoringSSL) ─────────────────────────────────────────
function bypassFlutterSSL() {
    try {
        const lib = Module.findBaseAddress('libflutter.so');
        if (lib) {
            // ssl_crypto_x509_session_verify_cert_chain
            const pattern = '2d e9 f0 4f a3 b0 82 46 50 20 10 70';
            const matches = Memory.scan(lib, Process.findModuleByName('libflutter.so').size, pattern, {
                onMatch: function (address) {
                    Interceptor.attach(address, {
                        onLeave: function (retval) {
                            retval.replace(0x1);
                            warn('Flutter/BoringSSL cert verification bypassed');
                        }
                    });
                },
                onComplete: function () {}
            });
            log('Flutter SSL scan applied');
            bypassed++;
        }
    } catch (_) {}
}

// ─── Main ────────────────────────────────────────────────────────────────────
function main() {
    console.log(`\n${TAG} NightOwl SSL Pinning Bypass v3.0`);
    console.log(`${TAG} Applying all known bypass techniques...\n`);

    bypassOkHttp3();
    bypassTrustManagerImpl();
    bypassX509TrustManager();
    bypassWebViewSSL();
    bypassHostnameVerifier();
    bypassNetworkSecurityConfig();
    bypassTrustKit();
    bypassAppcelerator();
    bypassCordova();
    bypassFlutterSSL();

    console.log(`\n${TAG} SSL bypass complete: ${bypassed} techniques applied`);
    console.log(`${TAG} All HTTPS traffic should now be interceptable\n`);
}

Java.perform(main);
