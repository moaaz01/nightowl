/**
 * NightOwl — Memory Dump & Analysis Script
 * Dumps and searches memory of running Android applications
 *
 * Usage:
 *   frida -H 127.0.0.1:27042 -f com.example.app -l memory-dump.js --no-pause
 *   frida -U -n com.example.app -l memory-dump.js
 */

'use strict';

const TAG = '[NightOwl-Memory]';

function log(msg)  { console.log(`${TAG} [+] ${msg}`); }
function warn(msg) { console.log(`${TAG} [!] ${msg}`); }
function info(msg) { console.log(`${TAG} [*] ${msg}`); }

// ─── 1. List loaded modules ─────────────────────────────────────────────────
function listModules() {
    info('Loaded modules:');
    const modules = Process.enumerateModules();
    modules.forEach(function (m) {
        console.log(`  ${m.name.padEnd(40)} base=${m.base} size=${m.size}`);
    });
    log(`Total modules: ${modules.length}`);
    return modules;
}

// ─── 2. Search memory for string ────────────────────────────────────────────
function searchString(pattern) {
    info(`Searching memory for: "${pattern}"`);
    const ranges = Process.enumerateRanges('r--');
    let found = 0;

    ranges.forEach(function (range) {
        try {
            const matches = Memory.scanSync(range.base, range.size, stringToPattern(pattern));
            matches.forEach(function (match) {
                const context = readContext(match.address, 64);
                warn(`Found at ${match.address}: ${context}`);
                found++;
            });
        } catch (_) {}
    });

    log(`Search complete: ${found} matches for "${pattern}"`);
}

function stringToPattern(str) {
    let hex = '';
    for (let i = 0; i < str.length; i++) {
        hex += str.charCodeAt(i).toString(16).padStart(2, '0') + ' ';
    }
    return hex.trim();
}

function readContext(addr, size) {
    try {
        const buf = Memory.readByteArray(addr, size);
        if (!buf) return '<unreadable>';
        const arr = new Uint8Array(buf);
        let text = '';
        for (let i = 0; i < arr.length; i++) {
            const c = arr[i];
            text += (c >= 32 && c < 127) ? String.fromCharCode(c) : '.';
        }
        return text;
    } catch (_) {
        return '<unreadable>';
    }
}

// ─── 3. Dump module to file ─────────────────────────────────────────────────
function dumpModule(moduleName) {
    const mod = Process.findModuleByName(moduleName);
    if (!mod) {
        warn(`Module not found: ${moduleName}`);
        return;
    }

    info(`Dumping module: ${mod.name} (base=${mod.base}, size=${mod.size})`);
    const outPath = `/data/local/tmp/nightowl_dump_${mod.name}`;

    try {
        const buf = Memory.readByteArray(mod.base, mod.size);
        const f = new File(outPath, 'wb');
        f.write(buf);
        f.flush();
        f.close();
        log(`Module dumped to: ${outPath}`);
        log(`Pull with: adb pull ${outPath}`);
    } catch (e) {
        warn(`Dump failed: ${e}`);
    }
}

// ─── 4. Search for secrets in memory ────────────────────────────────────────
function scanSecrets() {
    info('Scanning memory for secrets...');
    const patterns = [
        { name: 'JWT Token',     search: 'eyJ' },
        { name: 'Bearer Token',  search: 'Bearer ' },
        { name: 'API Key',       search: 'api_key' },
        { name: 'API Key',       search: 'apikey' },
        { name: 'Password',      search: 'password' },
        { name: 'Secret',        search: 'secret' },
        { name: 'Private Key',   search: '-----BEGIN' },
        { name: 'AWS Key',       search: 'AKIA' },
        { name: 'Firebase',      search: 'AIzaSy' },
    ];

    const ranges = Process.enumerateRanges('r--');
    let totalFound = 0;

    patterns.forEach(function (p) {
        let found = 0;
        const hexPattern = stringToPattern(p.search);

        ranges.forEach(function (range) {
            try {
                const matches = Memory.scanSync(range.base, range.size, hexPattern);
                matches.forEach(function (match) {
                    if (found < 5) { // limit output per pattern
                        const ctx = readContext(match.address, 80);
                        warn(`[${p.name}] at ${match.address}: ${ctx}`);
                    }
                    found++;
                });
            } catch (_) {}
        });

        if (found > 0) {
            log(`${p.name}: ${found} occurrences`);
            totalFound += found;
        }
    });

    log(`Secret scan complete: ${totalFound} potential secrets found`);
}

// ─── 5. Monitor memory allocations ──────────────────────────────────────────
function monitorMalloc(minSize) {
    minSize = minSize || 1024;
    info(`Monitoring malloc() calls >= ${minSize} bytes`);

    Interceptor.attach(Module.findExportByName(null, 'malloc'), {
        onEnter: function (args) {
            this.size = args[0].toInt32();
        },
        onLeave: function (retval) {
            if (this.size >= minSize) {
                info(`malloc(${this.size}) => ${retval}`);
            }
        }
    });

    log('malloc monitor active');
}

// ─── 6. Dump class fields (Java) ────────────────────────────────────────────
function dumpClassFields(className) {
    Java.perform(function () {
        try {
            const clazz = Java.use(className);
            const fields = clazz.class.getDeclaredFields();
            info(`Fields of ${className}:`);
            for (let i = 0; i < fields.length; i++) {
                fields[i].setAccessible(true);
                console.log(`  ${fields[i].getType().getName()} ${fields[i].getName()}`);
            }
        } catch (e) {
            warn(`Cannot dump class ${className}: ${e}`);
        }
    });
}

// ─── 7. Enumerate Java classes matching pattern ─────────────────────────────
function findClasses(pattern) {
    Java.perform(function () {
        info(`Searching for classes matching: ${pattern}`);
        const re = new RegExp(pattern, 'i');
        let count = 0;

        Java.enumerateLoadedClasses({
            onMatch: function (name) {
                if (re.test(name)) {
                    console.log(`  ${name}`);
                    count++;
                }
            },
            onComplete: function () {
                log(`Found ${count} matching classes`);
            }
        });
    });
}

// ─── 8. Dump SharedPreferences ──────────────────────────────────────────────
function dumpSharedPrefs() {
    Java.perform(function () {
        try {
            const ctx = Java.use('android.app.ActivityThread')
                .currentApplication().getApplicationContext();
            const prefsDir = ctx.getFilesDir().getParentFile().getAbsolutePath() + '/shared_prefs';
            const File = Java.use('java.io.File');
            const dir = File.$new(prefsDir);

            info(`SharedPreferences directory: ${prefsDir}`);

            if (dir.exists()) {
                const files = dir.listFiles();
                for (let i = 0; i < files.length; i++) {
                    console.log(`  ${files[i].getName()}`);
                }
                log(`Total SharedPrefs files: ${files.length}`);
            }
        } catch (e) {
            warn(`Cannot access SharedPreferences: ${e}`);
        }
    });
}

// ─── Main ────────────────────────────────────────────────────────────────────
function main() {
    console.log(`\n${TAG} NightOwl Memory Analysis v3.0\n`);

    // Auto-run basic analysis
    listModules();
    console.log('');
    scanSecrets();
    console.log('');
    dumpSharedPrefs();

    console.log(`
${TAG} ═══════════════════════════════════════
${TAG}  Interactive functions available:
${TAG}    searchString("password")
${TAG}    dumpModule("libapp.so")
${TAG}    scanSecrets()
${TAG}    monitorMalloc(4096)
${TAG}    dumpClassFields("com.app.MyClass")
${TAG}    findClasses("auth|login|token")
${TAG}    dumpSharedPrefs()
${TAG}    listModules()
${TAG} ═══════════════════════════════════════
`);
}

// Export functions for interactive use
rpc.exports = {
    searchstring: searchString,
    dumpmodule: dumpModule,
    scansecrets: scanSecrets,
    monitormalloc: monitorMalloc,
    dumpclassfields: dumpClassFields,
    findclasses: findClasses,
    dumpsharedprefs: dumpSharedPrefs,
    listmodules: listModules,
};

Java.perform(main);
