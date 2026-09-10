import os
import sys
import subprocess
import crypto_engine

# Ensure UTF-8 output on Windows console
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

def test_cross_compatibility():
    print("==================================================")
    print("TESTING PYTHON <-> JAVA CRYPTO INTEROPERABILITY")
    print("==================================================")

    password = "MasterVaultSecret#2026!"
    original_text = "Zero-Knowledge Aegis Interoperability Test Payload across Python and Java SE.\n" * 100

    # 1. Write original file
    with open("data/interop_original.txt", "w", encoding="utf-8") as f:
        f.write(original_text)

    # 2. Encrypt with Python crypto_engine.py
    print("1. Encrypting with Python crypto_engine...")
    crypto_engine.encrypt_file("data/interop_original.txt", "data/interop_py_enc.vault", password)
    assert os.path.exists("data/interop_py_enc.vault"), "Python encrypted file not found"

    # 3. Decrypt with Java JavaCryptoEngine
    print("2. Decrypting with Java JavaCryptoEngine...")
    java_decrypt_code = f"""
import com.aegis.crypto.JavaCryptoEngine;
import java.io.File;

public class JavaDecryptBridge {{
    public static void main(String[] args) throws Exception {{
        JavaCryptoEngine.decryptFile(
            new File("data/interop_py_enc.vault"),
            new File("data/interop_java_dec.txt"),
            "{password}".toCharArray(),
            null
        );
        System.out.println("Java Decryption Done.");
    }}
}}
"""
    with open("java_auth/src/JavaDecryptBridge.java", "w", encoding="utf-8") as f:
        f.write(java_decrypt_code)

    subprocess.run(["javac", "-d", "bin", "-sourcepath", "java_auth/src", "java_auth/src/JavaDecryptBridge.java"], check=True)
    subprocess.run(["java", "-cp", "bin", "JavaDecryptBridge"], check=True)

    with open("data/interop_java_dec.txt", "r", encoding="utf-8") as f:
        java_dec_text = f.read()

    assert java_dec_text == original_text, "Java decrypted text does not match original Python plaintext!"
    print("  [PASS]: Python Encrypted -> Java Decrypted Successfully (100% Match)")

    # 4. Encrypt with Java JavaCryptoEngine
    print("3. Encrypting with Java JavaCryptoEngine...")
    java_encrypt_code = f"""
import com.aegis.crypto.JavaCryptoEngine;
import java.io.File;

public class JavaEncryptBridge {{
    public static void main(String[] args) throws Exception {{
        JavaCryptoEngine.encryptFile(
            new File("data/interop_original.txt"),
            new File("data/interop_java_enc.vault"),
            "{password}".toCharArray(),
            null
        );
        System.out.println("Java Encryption Done.");
    }}
}}
"""
    with open("java_auth/src/JavaEncryptBridge.java", "w", encoding="utf-8") as f:
        f.write(java_encrypt_code)

    subprocess.run(["javac", "-d", "bin", "-sourcepath", "java_auth/src", "java_auth/src/JavaEncryptBridge.java"], check=True)
    subprocess.run(["java", "-cp", "bin", "JavaEncryptBridge"], check=True)

    # 5. Decrypt with Python crypto_engine.py
    print("4. Decrypting with Python crypto_engine...")
    crypto_engine.decrypt_file("data/interop_java_enc.vault", "data/interop_py_dec.txt", password)

    with open("data/interop_py_dec.txt", "r", encoding="utf-8") as f:
        py_dec_text = f.read()

    assert py_dec_text == original_text, "Python decrypted text does not match original Java plaintext!"
    print("  [PASS]: Java Encrypted -> Python Decrypted Successfully (100% Match)")

    # Cleanup temp files
    for p in ["data/interop_original.txt", "data/interop_py_enc.vault", "data/interop_java_dec.txt",
              "data/interop_java_enc.vault", "data/interop_py_dec.txt",
              "java_auth/src/JavaDecryptBridge.java", "java_auth/src/JavaEncryptBridge.java"]:
        if os.path.exists(p):
            os.remove(p)

    print("\n[SUCCESS] ALL INTEROPERABILITY TESTS PASSED WITH 100% BIT-FOR-BIT ACCURACY!")

if __name__ == "__main__":
    test_cross_compatibility()
