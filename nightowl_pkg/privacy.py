# privacy.py -- NightOwl v8 Tracker & Privacy Surface Audit
#
# Exodus-Privacy-inspired tracker detection from embedded SDK class names,
# plus a privacy-relevant permission view (data-collection surface).
# Helps answer: "Who does this app talk about me to?"

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

TRACKERS = {
    # Analytics / measurement
    "Google Analytics": ["com.google.android.gms.analytics", "com.google.analytics"],
    "Google Firebase Analytics": ["com.google.firebase.analytics",
                                  "FirebaseAnalytics"],
    "Google Tag Manager": ["com.google.android.gms.tagmanager"],
    "Facebook Analytics/Graph": ["com.facebook.appevents", "AppEventsLogger",
                                 "com.facebook.GraphRequest"],
    "Adjust": ["com.adjust.sdk"],
    "AppsFlyer": ["com.appsflyer"],
    "Amplitude": ["com.amplitude.api"],
    "Mixpanel": ["com.mixpanel.android"],
    "Flurry": ["com.flurry.android"],
    "Branch": ["io.branch.referral"],
    "Kochava": ["com.kochava"],
    "Countly": ["ly.count.android"],
    "Yandex AppMetrica": ["com.yandex.metrica"],
    "Huawei Analytics": ["com.huawei.hms.analytics"],
    "Comscore": ["com.comscore"],
    "Segment": ["com.segment.analytics"],
    "Matomo/Piwik": ["org.matomo", "org.piwik"],
    "Sentry (crash)": ["io.sentry"],
    "Bugsnag": ["com.bugsnag"],
    "Crashlytics": ["com.crashlytics", "com.google.firebase.crashlytics"],
    "Instabug": ["com.instabug"],
    "Firebase Crashlytics": ["FirebaseCrashlytics"],
    # Ads
    "Google AdMob": ["com.google.android.gms.ads", "com.google.android.gms.internal.ads"],
    "Google DoubleClick": ["com.google.ads.doubleclick", "m.google.sdk.modules"],
    "Unity Ads": ["com.unity3d.ads"],
    "AppLovin": ["com.applovin"],
    "ironSource": ["com.ironsource"],
    "Vungle": ["com.vungle"],
    "AdColony": ["com.adcolony"],
    "MoPub": ["com.mopub"],
    "InMobi": ["com.inmobi"],
    "Tapjoy": ["com.tapjoy"],
    "StartApp": ["com.startapp"],
    "Chartboost": ["com.chartboost"],
    "Fyber": ["com.fyber"],
    "Smaato": ["com.smaato"],
    "Smart Ad Server": ["com.smartadserver"],
    "PubNative": ["net.pubnative"],
    "TikTok Ads": ["com.bytedance.sdk.openadsdk", "com.tiktok"],
    "Twitter/X MoPub": ["com.mopub.mobileads"],
    "Meta Audience Network": ["com.facebook.ads"],
    # Social login / identity
    "Facebook Login": ["com.facebook.login"],
    "Google Sign-In": ["com.google.android.gms.auth"],
    "Twitter4J": ["twitter4j"],
    # Push / messaging
    "OneSignal": ["com.onesignal"],
    "Firebase Messaging (FCM)": ["com.google.firebase.messaging"],
    "Airship": ["com.urbanairship"],
    "CleverTap": ["com.clevertap"],
    "Braze": ["com.braze", "com.appboy"],
}

# Permissions that reveal data-collection posture
PRIVACY_PERMS = {
    "android.permission.ACCESS_FINE_LOCATION": ("Precise location", "location"),
    "android.permission.ACCESS_COARSE_LOCATION": ("Approximate location", "location"),
    "android.permission.READ_CONTACTS": ("Read contacts", "contacts"),
    "android.permission.READ_CALL_LOG": ("Call history", "calls"),
    "android.permission.READ_PHONE_STATE": ("Device identifiers/phone state", "identifiers"),
    "android.permission.RECORD_AUDIO": ("Microphone", "audio"),
    "android.permission.CAMERA": ("Camera", "camera"),
    "android.permission.READ_SMS": ("SMS content", "sms"),
    "android.permission.BODY_SENSORS": ("Body sensors", "health"),
    "android.permission.READ_MEDIA_IMAGES": ("Photos", "media"),
    "android.permission.GET_ACCOUNTS": ("Device accounts", "accounts"),
    "android.permission.BLUETOOTH_SCAN": ("Bluetooth scanning (proximity)", "proximity"),
}


def analyze_privacy(txt, perms_dangerous=None):
    """Tracker inventory + data-collection permission map."""
    found = {}
    low = txt.lower()
    for name, markers in TRACKERS.items():
        hits = sorted({m for m in markers if m.lower() in low and "?" not in m})
        if hits:
            found[name] = hits[:3]

    categories = {}
    perm_rows = []
    for p in perms_dangerous or []:
        name = p.get("name") if isinstance(p, dict) else str(p)
        risk = p.get("risk") if isinstance(p, dict) else ""
        info = PRIVACY_PERMS.get(name)
        if info:
            label, cat = info
            perm_rows.append({"permission": name.split(".")[-1], "exposes": label,
                              "category": cat, "risk": risk})
            categories[cat] = categories.get(cat, 0) + 1

    ad_trackers = [n for n in found if n in (
        "Google AdMob", "Unity Ads", "AppLovin", "ironSource", "Vungle",
        "AdColony", "MoPub", "InMobi", "Tapjoy", "StartApp", "Chartboost",
        "Fyber", "Smaato", "Smart Ad Server", "PubNative", "TikTok Ads",
        "Meta Audience Network")]
    analytics = [n for n in found if n not in ad_trackers]

    findings = []
    if ad_trackers:
        findings.append({
            "severity": "LOW" if len(ad_trackers) < 3 else "MEDIUM",
            "title": f"{len(ad_trackers)} advertising SDK(s) embedded",
            "detail": "Ad SDKs typically collect device identifiers and "
                      "approximate location for targeting.",
            "evidence": sorted(ad_trackers),
        })
    if len(analytics) >= 5:
        findings.append({
            "severity": "LOW",
            "title": f"{len(analytics)} distinct analytics/crash SDK(s)",
            "detail": "Wide telemetry surface - each is an independent data "
                      "destination worth listing in the privacy policy.",
            "evidence": sorted(analytics)[:10],
        })

    return {
        "module": "privacy-trackers",
        "trackers": {k: v for k, v in found.items()},
        "tracker_count": len(found),
        "ad_sdk_count": len(ad_trackers),
        "analytics_count": len(analytics),
        "data_collection_permissions": perm_rows,
        "collection_categories": categories,
        "findings": findings,
    }


def cmd_privacy(apk_path: str, analyzer=None, json_out=False):
    """CLI handler: nightowl privacy <apk>"""
    from . import core as nw
    az = analyzer
    if az is None:
        az = nw.NightOwlAnalyzer(apk_path)
        az.extract_strings()
        az.analyze_perms()
    rep = analyze_privacy(az.txt, az.d["perms"].get("dangerous"))
    if json_out:
        import json as _json
        print(_json.dumps(rep, indent=2, ensure_ascii=False))
        return rep

    print("\n=== Privacy & Tracker Audit ===")
    print(f"Trackers detected : {rep['tracker_count']} "
          f"(ads: {rep['ad_sdk_count']}, analytics/crash: {rep['analytics_count']})")
    for name in sorted(rep["trackers"]):
        print(f"  - {name}")
    if rep["data_collection_permissions"]:
        print("Data-collection permissions:")
        for r in rep["data_collection_permissions"]:
            print(f"  [{r['risk'] or '-':8}] {r['permission']:24} -> {r['exposes']}")
    return rep
