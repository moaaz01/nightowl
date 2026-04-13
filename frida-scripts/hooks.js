/**
 * Frida Hook Collection for Android Analysis
 * Attach to running Android app to intercept and monitor function calls
 *
 * Usage:
 *   frida -H 127.0.0.1:27042 -f com.example.app -l hooks.js
 *   frida -U -f com.example.app -l hooks.js  (USB device)
 */

// ============================================================================
// GLOBAL UTILITIES
// ============================================================================

const TAG = "[HOOKS]";

function log_info(msg) {
    console.log(`${TAG} [*] ${msg}`);
}

function log_success(msg) {
    console.log(`${TAG} [+] ${msg}`);
}

function log_error(msg) {
    console.log(`${TAG} [-] ${msg}`);
}

function log_warning(msg) {
    console.log(`${TAG} [!] ${msg}`);
}

// ============================================================================
// 1. FUNCTION INTERCEPTION - Hook specific methods
// ============================================================================

function hook_function(target, signature) {
    /**
     * Hook a Java method
     * target: e.g., "com.example.app.AuthManager"
     * signature: e.g., "checkPassword(java.lang.String)"
     */
    try {
        const clazz = Java.use(target);
        const method_name = signature.split('(')[0];

        clazz[method_name].overload(...signature.match(/\((.*?)\)/)[1].split(',')).implementation = function() {
            log_success(`Called: ${target}.${signature}`);
            console.log(`  Args: ${JSON.stringify(arguments)}`);

            const result = this[method_name].apply(this, arguments);
            console.log(`  Result: ${result}`);
            return result;
        };

        log_success(`Hooked: ${target}.${signature}`);
    } catch (error) {
        log_error(`Failed to hook ${target}.${signature}: ${error}`);
    }
}

// ============================================================================
// 2. CRYPTO INTERCEPTION - Monitor crypto operations
// ============================================================================

function hook_crypto_operations() {
    log_info("Hooking crypto operations...");

    // Hook Cipher.getInstance
    try {
        const Cipher = Java.use("javax.crypto.Cipher");
        const getInstance = Cipher.getInstance.overload("java.lang.String");

        getInstance.implementation = function(transformation) {
            log_success(`Cipher.getInstance: ${transformation}`);
            return getInstance.call(this, transformation);
        };
    } catch (e) {
        log_warning(`Cipher hook failed: ${e}`);
    }

    // Hook SecretKeySpec
    try {
        const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function(key, algorithm) {
            log_success(`SecretKeySpec created: ${algorithm}, Key length: ${key.length}`);
            log_warning(`KEY (hex): ${bytes_to_hex(key)}`);
            return this.$init(key, algorithm);
        };
    } catch (e) {
        log_warning(`SecretKeySpec hook failed: ${e}`);
    }

    // Hook MessageDigest
    try {
        const MessageDigest = Java.use("java.security.MessageDigest");
        const getInstance = MessageDigest.getInstance.overload("java.lang.String");

        getInstance.implementation = function(algorithm) {
            log_success(`MessageDigest.getInstance: ${algorithm}`);
            return getInstance.call(this, algorithm);
        };
    } catch (e) {
        log_warning(`MessageDigest hook failed: ${e}`);
    }
}

// ============================================================================
// 3. FILE OPERATIONS - Monitor file access
// ============================================================================

function hook_file_operations() {
    log_info("Hooking file operations...");

    try {
        const FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload("java.lang.String").implementation = function(filename) {
            log_success(`FileInputStream opened: ${filename}`);
            return this.$init(filename);
        };
    } catch (e) {
        log_warning(`FileInputStream hook failed: ${e}`);
    }

    try {
        const FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload("java.lang.String").implementation = function(filename) {
            log_success(`FileOutputStream opened: ${filename}`);
            return this.$init(filename);
        };
    } catch (e) {
        log_warning(`FileOutputStream hook failed: ${e}`);
    }

    try {
        const File = Java.use("java.io.File");
        File.$init.overload("java.lang.String").implementation = function(path) {
            log_success(`File created: ${path}`);
            return this.$init(path);
        };
    } catch (e) {
        log_warning(`File hook failed: ${e}`);
    }
}

// ============================================================================
// 4. NETWORK OPERATIONS - Monitor network calls
// ============================================================================

function hook_network_operations() {
    log_info("Hooking network operations...");

    // HttpURLConnection
    try {
        const HttpURLConnection = Java.use("java.net.HttpURLConnection");
        const getInputStream = HttpURLConnection.getInputStream;

        getInputStream.implementation = function() {
            log_success(`HTTP Connection to: ${this.getURL()}`);
            log_warning(`Method: ${this.getRequestMethod()}`);
            return getInputStream.call(this);
        };
    } catch (e) {
        log_warning(`HttpURLConnection hook failed: ${e}`);
    }

    // URLConnection.connect
    try {
        const URLConnection = Java.use("java.net.URLConnection");
        const connect = URLConnection.connect;

        connect.implementation = function() {
            log_success(`Connecting to: ${this.getURL()}`);
            return connect.call(this);
        };
    } catch (e) {
        log_warning(`URLConnection hook failed: ${e}`);
    }

    // Socket creation
    try {
        const Socket = Java.use("java.net.Socket");
        Socket.$init.overload("java.lang.String", "int").implementation = function(host, port) {
            log_success(`Socket connection: ${host}:${port}`);
            return this.$init(host, port);
        };
    } catch (e) {
        log_warning(`Socket hook failed: ${e}`);
    }
}

// ============================================================================
// 5. SHARED PREFERENCES - Monitor shared preferences access
// ============================================================================

function hook_shared_preferences() {
    log_info("Hooking SharedPreferences...");

    try {
        const SharedPreferences = Java.use("android.content.SharedPreferences");
        const getString = SharedPreferences.getString;

        getString.implementation = function(key, defValue) {
            const value = getString.call(this, key, defValue);
            log_warning(`SharedPreferences.getString("${key}") = "${value}"`);
            return value;
        };
    } catch (e) {
        log_warning(`SharedPreferences hook failed: ${e}`);
    }
}

// ============================================================================
// 6. AUTHENTICATION - Monitor authentication calls
// ============================================================================

function hook_authentication() {
    log_info("Hooking authentication calls...");

    // Note: Runtime.exec is hooked in hook_native_operations() to avoid double-hooking
    // Auth method hooking (login, verify, etc.) requires per-app class names
    // which are discovered during analysis and hooked interactively via Frida REPL

    log_info("Authentication monitoring ready (use hook_function for app-specific auth methods)");
}

// ============================================================================
// 7. REFLECTION - Monitor reflection calls
// ============================================================================

function hook_reflection() {
    log_info("Hooking reflection operations...");

    try {
        const Method = Java.use("java.lang.reflect.Method");
        const invoke = Method.invoke;

        invoke.implementation = function(obj, args) {
            log_warning(`Reflection invoke: ${this.getDeclaringClass().getName()}.${this.getName()}`);
            return invoke.call(this, obj, args);
        };
    } catch (e) {
        log_warning(`Reflection hook failed: ${e}`);
    }
}

// ============================================================================
// 8. NATIVE BRIDGES - Hook native method calls
// ============================================================================

function hook_native_operations() {
    log_info("Hooking native operations...");

    try {
        const Runtime = Java.use("java.lang.Runtime");

        Runtime.getRuntime().exec.overload("java.lang.String").implementation = function(cmd) {
            log_error(`NATIVE COMMAND EXECUTED: ${cmd}`);
            return Runtime.getRuntime().exec.call(this, cmd);
        };
    } catch (e) {
        log_warning(`Native operations hook failed: ${e}`);
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function bytes_to_hex(bytes) {
    let result = "";
    for (let i = 0; i < bytes.length; i++) {
        result += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
    }
    return result;
}

function dump_object(obj, depth = 1) {
    if (depth > 3) return "[...]";

    const props = Object.getOwnPropertyNames(obj);
    let result = "{\n";

    for (let prop of props) {
        try {
            const val = obj[prop];
            result += `  ${prop}: ${typeof val === 'object' ? dump_object(val, depth + 1) : val}\n`;
        } catch (e) {
            result += `  ${prop}: [ERROR]\n`;
        }
    }

    result += "}";
    return result;
}

// ============================================================================
// MAIN EXECUTION
// ============================================================================

function main() {
    log_info("Frida hooks loading...");
    log_info(`Process: ${Process.id}`);
    log_info(`App: ${Java.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName()}`);

    console.log("\n=== STARTING HOOK INITIALIZATION ===\n");

    // Enable/disable hooks as needed
    hook_crypto_operations();
    hook_file_operations();
    hook_network_operations();
    hook_shared_preferences();
    hook_authentication();
    hook_reflection();
    hook_native_operations();

    console.log("\n=== HOOKS INITIALIZED ===\n");
}

// Run main when Frida is ready
if (Java.available) {
    main();
} else {
    Java.perform(main);
}
