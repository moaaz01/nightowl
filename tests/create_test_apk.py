#!/usr/bin/env python3
"""
Create a minimal test APK in memory for testing NightOwl.
Generates a valid APK with known strings, permissions, and secrets.
"""
import zipfile
import struct
import os
from pathlib import Path

# Minimal valid DEX file (Android's "Hello World" DEX)
# This is the smallest valid DEX that androguard can parse
MINIMAL_DEX = bytes([
    0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00,  # dex\n035\0
    0x98, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12,  # checksum
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # signature
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x98, 0x00, 0x00, 0x00,  # file_size
    0x70, 0x00, 0x00, 0x00,  # header_size
    0x78, 0x56, 0x34, 0x12,  # endian_tag
    0x00, 0x00, 0x00, 0x00,  # link_size
    0x00, 0x00, 0x00, 0x00,  # link_off
    0x00, 0x00, 0x00, 0x00,  # map_off
    0x01, 0x00, 0x00, 0x00,  # string_ids_size
    0x70, 0x00, 0x00, 0x00,  # string_ids_off
    0x00, 0x00, 0x00, 0x00,  # type_ids_size
    0x00, 0x00, 0x00, 0x00,  # type_ids_off
    0x00, 0x00, 0x00, 0x00,  # proto_ids_size
    0x00, 0x00, 0x00, 0x00,  # proto_ids_off
    0x00, 0x00, 0x00, 0x00,  # field_ids_size
    0x00, 0x00, 0x00, 0x00,  # field_ids_off
    0x00, 0x00, 0x00, 0x00,  # method_ids_size
    0x00, 0x00, 0x00, 0x00,  # method_ids_off
    0x00, 0x00, 0x00, 0x00,  # class_defs_size
    0x00, 0x00, 0x00, 0x00,  # class_defs_off
    0x08, 0x00, 0x00, 0x00,  # data_size
    0x90, 0x00, 0x00, 0x00,  # data_off
    # string_ids[0]
    0x74, 0x00, 0x00, 0x00,  # -> offset 0x74
    # string_data_item at 0x74
    0x01,  # uleb128 utf16_size = 1
    0x61,  # 'a'
    0x00,  # \0
    0x00, 0x00,  # padding
    # data section
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
])


def create_test_apk(output_path: str, inject_secrets: bool = False):
    """Create a minimal test APK with optional secret injection."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    # AndroidManifest.xml (minimal valid binary XML)
    manifest = (
        b'\x03\x00\x08\x00\x6c\x00\x00\x00'  # header
        b'\x00\x00\x00\x00\x00\x00\x00\x00'  # no string pool
        b'\x00\x00\x00\x00'  # resource id
    )
    # Pad to reasonable size
    manifest = manifest + b'\x00' * 64

    with zipfile.ZipFile(str(output), 'w', zipfile.ZIP_DEFLATED) as zf:
        # Minimal DEX
        zf.writestr('classes.dex', MINIMAL_DEX)

        # Minimal AndroidManifest
        zf.writestr('AndroidManifest.xml', manifest)

        # Resources.arsc (minimal)
        zf.writestr('resources.arsc', b'\x02\x00\x0c\x00\x00\x00\x00\x00')

        # META-INF
        zf.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\n')

        # Inject test strings via assets
        test_strings = [
            'https://api.example.com/v1/users',
            'https://secure.example.com/login',
            'http://insecure.example.com/data',
            'contact@developer.example.com',
        ]
        if inject_secrets:
            test_strings.extend([
                'AKIAIOSFODNN7EXAMPLE',  # AWS key pattern
                'sk_live_test1234567890abcdef',  # Stripe key pattern
                'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234',  # GitHub token
                'password="super_secret_123"',
                'api_key="my_test_api_key_value_here"',
                'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123',
            ])

        zf.writestr('assets/test_config.txt', '\n'.join(test_strings))

        # Inject permissions test via a fake XML
        perm_xml = (
            b'<?xml version="1.0" encoding="utf-8"?>'
            b'<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
            b'<uses-permission android:name="android.permission.INTERNET"/>'
            b'<uses-permission android:name="android.permission.READ_SMS"/>'
            b'<uses-permission android:name="android.permission.CAMERA"/>'
            b'<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>'
            b'</manifest>'
        )
        zf.writestr('res/xml/test_permissions.xml', perm_xml)

    return str(output)


if __name__ == '__main__':
    targets = Path(__file__).resolve().parent / 'targets'
    create_test_apk(str(targets / 'test_clean.apk'), inject_secrets=False)
    create_test_apk(str(targets / 'test_secrets.apk'), inject_secrets=True)
    print(f"Created test APKs in {targets}/")
