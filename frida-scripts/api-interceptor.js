/**
 * NightOwl — Advanced API & Network Interceptor
 * Captures ALL HTTP/HTTPS requests, responses, headers, and bodies at runtime
 *
 * Usage:
 *   frida -H 127.0.0.1:27042 -f com.example.app -l api-interceptor.js --no-pause
 *   frida -U -n com.example.app -l api-interceptor.js
 *
 * What it captures:
 *   ✅ All HTTP/HTTPS URLs with method & body
 *   ✅ Request headers (Authorization, tokens, cookies)
 *   ✅ Response bodies (JSON, HTML, plain text)
 *   ✅ OkHttp, Retrofit, HttpURLConnection, Volley
 *   ✅ WebView requests
 *   ✅ SSL pinning bypass (automatic)
 *   ✅ Root detection bypass
 */

'use strict';

const TAG = '[NightOwl-Intercept]';
const captured = { requests: [], secrets: new Set() };

// ─── Utilities ────────────────────────────────────────────────────────────────
const log  = m  => console.log(`${TAG} [*] ${m}`);
const warn = m  => console.log(`${TAG} [!] ${m}`);
const info = m  => console.log(`${TAG} [+] ${m}`);
const err  = (m, e) => console.log(`${TAG} [-] ${m}: ${e}`);

function trunc(s, n = 500) {
    s = String(s);
    return s.length > n ? s.slice(0, n) + `…[+${s.length - n}]` : s;
}

function tryJson(s) {
    try { return JSON.stringify(JSON.parse(s), null, 2); } catch (_) { return s; }
}

function record(req) {
    captured.requests.push(req);
    const hdrs = Object.entries(req.headers || {}).map(([k, v]) => `    ${k}: ${v}`).join('\n');
    console.log(`
╔──────────────────────────────────────────────────
║ ${req.method} ${req.url}
${hdrs ? '║ Headers:\n' + hdrs : ''}
${req.body ? '║ Body:\n    ' + trunc(req.body) : ''}
${req.response ? '║ Response [' + req.status + ']:\n    ' + trunc(req.response) : ''}
╚──────────────────────────────────────────────────`);
}


// ─── 1. OkHttp Interceptor ────────────────────────────────────────────────────
function hookOkHttp() {
    try {
        // OkHttp3
        const Interceptor = Java.use('okhttp3.Interceptor');
        const Chain       = Java.use('okhttp3.Interceptor$Chain');
        const OkHttpClient = Java.use('okhttp3.OkHttpClient');
        const Builder     = Java.use('okhttp3.OkHttpClient$Builder');

        Builder.build.implementation = function () {
            const addNetworkInterceptor = this.addNetworkInterceptor.bind(this);
            const interceptor = Java.implement(Interceptor, {
                intercept(chain) {
                    const request  = chain.request();
                    const url      = request.url().toString();
                    const method   = request.method();

                    // Extract headers
                    const hdrMap = {};
                    const names  = request.headers().names().toArray();
                    for (const n of names) {
                        hdrMap[n] = request.headers().get(n);
                        // flag sensitive headers
                        if (/auth|token|secret|key|bearer/i.test(n)) {
                            warn(`Sensitive Header ➜ ${n}: ${request.headers().get(n)}`);
                        }
                    }

                    // Read request body
                    let body = '';
                    try {
                        const rb = request.body();
                        if (rb) {
                            const Buffer = Java.use('okio.Buffer');
                            const buf = Buffer.$new();
                            rb.writeTo(buf);
                            body = buf.readUtf8();
                        }
                    } catch (_) {}

                    const response = chain.proceed(request);

                    // Read response body (clone so stream stays open)
                    let resBody = '';
                    try {
                        const resClone = response.peekBody(1024 * 1024).string();
                        resBody = tryJson(resClone);
                    } catch (_) {}

                    record({
                        url, method,
                        headers: hdrMap,
                        body,
                        status:   response.code(),
                        response: resBody,
                    });

                    return response;
                }
            });
            addNetworkInterceptor(interceptor);
            return this.build.call(this);
        };

        info('OkHttp3 interceptor attached');
    } catch (_) {}

    try {
        // OkHttp2
        const OkHttpClient2 = Java.use('com.squareup.okhttp.OkHttpClient');
        OkHttpClient2.open.implementation = function (req) {
            info(`[OkHttp2] ${req.getUrl()}`);
            return this.open(req);
        };
        info('OkHttp2 interceptor attached');
    } catch (_) {}
}


// ─── 2. HttpURLConnection Interceptor ────────────────────────────────────────
function hookHttpURLConnection() {
    try {
        const URLConn = Java.use('java.net.HttpURLConnection');

        URLConn.getInputStream.implementation = function () {
            const url = this.getURL().toString();
            const method = this.getRequestMethod();

            const headers = {};
            try {
                const props = this.getRequestProperties();
                const keys  = props.keySet().toArray();
                for (const k of keys) {
                    headers[k] = props.get(k).toString();
                }
            } catch (_) {}

            info(`[HttpURLConnection] ${method} ${url}`);
            record({ url, method, headers, body: '', status: this.getResponseCode() });
            return this.getInputStream();
        };

        info('HttpURLConnection interceptor attached');
    } catch (e) { err('HttpURLConnection hook failed', e); }
}


// ─── 3. WebView Interceptor ───────────────────────────────────────────────────
function hookWebView() {
    try {
        const WebViewClient = Java.use('android.webkit.WebViewClient');

        WebViewClient.shouldInterceptRequest.overload(
            'android.webkit.WebView', 'android.webkit.WebResourceRequest'
        ).implementation = function (wv, req) {
            const url    = req.getUrl().toString();
            const method = req.getMethod();
            const hdrs   = {};
            try {
                const jHdrs = req.getRequestHeaders();
                const keys  = jHdrs.keySet().toArray();
                for (const k of keys) hdrs[k] = jHdrs.get(k);
            } catch (_) {}

            if (!url.startsWith('data:') && !url.startsWith('blob:')) {
                info(`[WebView] ${method} ${url}`);
                record({ url, method, headers: hdrs });
            }
            return this.shouldInterceptRequest(wv, req);
        };

        info('WebView interceptor attached');
    } catch (e) { err('WebView hook failed', e); }
}


// ─── 4. SSL Pinning Bypass ────────────────────────────────────────────────────
function bypassSSLPinning() {
    // OkHttp3 CertificatePinner
    try {
        const CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function (h, _) {
            warn(`[SSL] CertificatePinner.check bypassed for ${h}`);
        };
        CertPinner.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function (h, _) {
            warn(`[SSL] CertificatePinner.check (cert) bypassed for ${h}`);
        };
        info('OkHttp3 SSL pinning bypassed');
    } catch (_) {}

    // TrustManagerImpl
    try {
        const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function (u, r, h, a, o, p) {
            warn(`[SSL] TrustManagerImpl.verifyChain bypassed for ${h}`);
            return u;
        };
        info('TrustManagerImpl SSL bypassed');
    } catch (_) {}

    // X509TrustManager
    try {
        const X509 = Java.use('javax.net.ssl.X509TrustManager');
        const SSLContext = Java.use('javax.net.ssl.SSLContext');
        const TrustAll = Java.implement(X509, {
            checkClientTrusted(_1, _2) {},
            checkServerTrusted(_1, _2) { warn('[SSL] X509 checkServerTrusted bypassed'); },
            getAcceptedIssuers() { return []; }
        });
        const ctx = SSLContext.getInstance('TLS');
        ctx.init(null, [TrustAll], null);
        SSLContext.getDefault.implementation = () => ctx;
        info('X509TrustManager bypassed');
    } catch (_) {}

    // WebViewClient
    try {
        const WVC = Java.use('android.webkit.WebViewClient');
        WVC.onReceivedSslError.implementation = function (wv, handler, _err) {
            warn('[SSL] WebViewClient.onReceivedSslError bypassed');
            handler.proceed();
        };
        info('WebViewClient SSL bypass applied');
    } catch (_) {}

    // HostnameVerifier
    try {
        const HttpsURLConn = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConn.setDefaultHostnameVerifier.implementation = function (_) {
            const AllowAll = Java.use('javax.net.ssl.HostnameVerifier');
            const verifier = Java.implement(AllowAll, {
                verify: (_h, _ss) => true
            });
            this.setDefaultHostnameVerifier(verifier);
            warn('[SSL] HostnameVerifier set to ALLOW_ALL');
        };
        info('HostnameVerifier bypassed');
    } catch (_) {}
}


// ─── 5. Root Detection Bypass ─────────────────────────────────────────────────
function bypassRootDetection() {
    const rootFiles = [
        '/system/app/Superuser.apk', '/sbin/su', '/system/bin/su',
        '/system/xbin/su', '/data/local/xbin/su', '/data/local/bin/su',
        '/system/sd/xbin/su', '/system/bin/.ext/.su',
    ];

    try {
        const File = Java.use('java.io.File');
        File.exists.implementation = function () {
            const path = this.getAbsolutePath();
            if (rootFiles.some(f => path.includes(f))) {
                warn(`[Root] File.exists("${path}") → false (bypassed)`);
                return false;
            }
            return this.exists();
        };
        info('Root file detection bypassed');
    } catch (_) {}

    try {
        const Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (cmd.includes('su') || cmd.includes('which')) {
                warn(`[Root] Runtime.exec("${cmd}") blocked`);
                return null;
            }
            return this.exec(cmd);
        };
        info('Runtime root exec bypass applied');
    } catch (_) {}
}


// ─── 6. Secret / Key Scanner ──────────────────────────────────────────────────
function scanForSecrets() {
    const PATTERNS = [
        { name: 'API Key',    re: /api[_-]?key\s*[:=]\s*["']?([a-zA-Z0-9_\-]{20,})/gi },
        { name: 'Auth Token', re: /auth[_-]?token\s*[:=]\s*["']?([a-zA-Z0-9_\-]{20,})/gi },
        { name: 'Bearer',     re: /Bearer\s+([a-zA-Z0-9_\-\.]{20,})/g },
        { name: 'JWT',        re: /eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+/g },
        { name: 'Password',   re: /password\s*[:=]\s*["']([^"']{6,})/gi },
    ];

    // Hook SharedPreferences getString — common secret storage
    try {
        const SharedPrefs = Java.use('android.app.SharedPreferencesImpl');
        SharedPrefs.getString.implementation = function (key, def) {
            const val = this.getString(key, def);
            if (val && val.length > 10) {
                PATTERNS.forEach(p => {
                    if (p.re.test(`${key}=${val}`)) {
                        const msg = `[SharedPrefs] Potential ${p.name} ➜ key="${key}" val="${val.slice(0, 20)}…"`;
                        if (!captured.secrets.has(msg)) {
                            captured.secrets.add(msg);
                            warn(msg);
                        }
                    }
                    p.re.lastIndex = 0;
                });
            }
            return val;
        };
        info('SharedPreferences secret scanner attached');
    } catch (_) {}
}


// ─── 7. Crypto Monitor ────────────────────────────────────────────────────────
function monitorCrypto() {
    // Cipher.getInstance
    try {
        const Cipher = Java.use('javax.crypto.Cipher');
        Cipher.getInstance.overload('java.lang.String').implementation = function (transformation) {
            warn(`[Crypto] Cipher.getInstance("${transformation}")`);
            return this.getInstance(transformation);
        };
        info('Cipher monitor attached');
    } catch (_) {}

    // SecretKeySpec — reveals actual encryption keys
    try {
        const SKSpec = Java.use('javax.crypto.spec.SecretKeySpec');
        SKSpec.$init.overload('[B', 'java.lang.String').implementation = function (keyBytes, alg) {
            const hex = Array.from(keyBytes).map(b => ('00' + (b & 0xff).toString(16)).slice(-2)).join('');
            warn(`[Crypto] SecretKeySpec created ➜ algo="${alg}" key_hex="${hex}"`);
            return this.$init(keyBytes, alg);
        };
        info('SecretKeySpec monitor attached');
    } catch (_) {}

    // MessageDigest
    try {
        const MD = Java.use('java.security.MessageDigest');
        MD.getInstance.overload('java.lang.String').implementation = function (alg) {
            if (/md5|sha-?1$/i.test(alg)) warn(`[Crypto] Weak digest: ${alg}`);
            return this.getInstance(alg);
        };
        info('MessageDigest monitor attached');
    } catch (_) {}
}


// ─── 8. Summary Dump ─────────────────────────────────────────────────────────
function printSummary() {
    setTimeout(() => {
        console.log(`\n${TAG} ═══════════════════════════════════════`);
        console.log(`${TAG}  CAPTURED SUMMARY`);
        console.log(`${TAG} ═══════════════════════════════════════`);
        console.log(`${TAG}  Total Requests: ${captured.requests.length}`);

        const uniq = [...new Set(captured.requests.map(r => r.url))];
        console.log(`${TAG}  Unique Endpoints: ${uniq.length}`);
        uniq.forEach(u => console.log(`${TAG}    ➜ ${u}`));

        if (captured.secrets.size > 0) {
            console.log(`${TAG}\n  Potential Secrets Found:`);
            captured.secrets.forEach(s => console.log(`${TAG}    🔑 ${s}`));
        }
        console.log(`${TAG} ═══════════════════════════════════════\n`);
    }, 30000); // print summary after 30 seconds
}


// ─── Main ─────────────────────────────────────────────────────────────────────
function main() {
    log('NightOwl API Interceptor loading…');
    log(`Process: PID=${Process.id}`);

    try {
        const pkg = Java.use('android.app.ActivityThread')
            .currentApplication().getApplicationContext().getPackageName();
        log(`App: ${pkg}`);
    } catch (_) {}

    console.log('\n  Applying hooks:\n');

    bypassSSLPinning();
    bypassRootDetection();
    hookOkHttp();
    hookHttpURLConnection();
    hookWebView();
    monitorCrypto();
    scanForSecrets();
    printSummary();

    console.log('\n  ✅ All hooks active — interact with the app now\n');
}

Java.perform(main);
