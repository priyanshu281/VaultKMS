package org.example;


import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.apache.hadoop.conf.Configuration;
import org.apache.parquet.crypto.KeyAccessDeniedException;
import org.apache.parquet.crypto.ParquetCryptoRuntimeException;
import org.apache.parquet.crypto.keytools.KeyToolkit;
import org.apache.parquet.crypto.keytools.KmsClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An example of KmsClient implementation. Not for production use!
 */
public class VaultClient implements KmsClient {
    private static final Logger LOG = LoggerFactory.getLogger(VaultClient.class);

    public static final String KEY_LIST_PROPERTY_NAME = "parquet.encryption.key.list";
    public static final String NEW_KEY_LIST_PROPERTY_NAME = "parquet.encryption.new.key.list";

    private static Map<String,byte[]> masterKeyMap;
    private static Map<String,byte[]> newMasterKeyMap;

    public static synchronized void startKeyRotation(Configuration hadoopConfiguration) {
        String[] newMasterKeys = hadoopConfiguration.getTrimmedStrings(NEW_KEY_LIST_PROPERTY_NAME);
        if (null == newMasterKeys || newMasterKeys.length == 0) {
            throw new ParquetCryptoRuntimeException("No encryption key list");
        }
        newMasterKeyMap = parseKeyList(newMasterKeys);
    }

    public static synchronized void finishKeyRotation() {
        masterKeyMap = newMasterKeyMap;
    }

    @Override
    public synchronized void initialize(Configuration configuration, String kmsInstanceID, String kmsInstanceURL, String accessToken) {
        // Parse master  keys
        String[] masterKeys = configuration.getTrimmedStrings(KEY_LIST_PROPERTY_NAME);
        if (null == masterKeys || masterKeys.length == 0) {
            throw new ParquetCryptoRuntimeException("No encryption key list");
        }
        masterKeyMap = parseKeyList(masterKeys);

        newMasterKeyMap = masterKeyMap;
    }

    private static Map<String, byte[]> parseKeyList(String[] masterKeys) {
        Map<String,byte[]> keyMap = new HashMap<>();

        int nKeys = masterKeys.length;
        for (int i=0; i < nKeys; i++) {
            String[] parts = masterKeys[i].split(":");
            String keyName = parts[0].trim();
            if (parts.length != 2) {
                throw new IllegalArgumentException("Key '" + keyName + "' is not formatted correctly");
            }
            String key = parts[1].trim();
            try {
                byte[] keyBytes = Base64.getDecoder().decode(key);
                keyMap.put(keyName, keyBytes);
            } catch (IllegalArgumentException e) {
                LOG.warn("Could not decode key '" + keyName + "'!");
                throw e;
            }
        }
        return keyMap;
    }

    @Override
    public synchronized String wrapKey(byte[] keyBytes, String masterKeyIdentifier)
            throws KeyAccessDeniedException, UnsupportedOperationException {

        // Always use the latest key version for writing
        byte[] masterKey = newMasterKeyMap.get(masterKeyIdentifier);
        if (null == masterKey) {
            throw new ParquetCryptoRuntimeException("Key not found: " + masterKeyIdentifier);
        }
        byte[] AAD = masterKeyIdentifier.getBytes(StandardCharsets.UTF_8);
        return KeyToolkit.encryptKeyLocally(keyBytes, masterKey, AAD);
    }

    @Override
    public synchronized byte[] unwrapKey(String wrappedKey, String masterKeyIdentifier)
            throws KeyAccessDeniedException, UnsupportedOperationException {
        byte[] masterKey = masterKeyMap.get(masterKeyIdentifier);
        if (null == masterKey) {
            throw new ParquetCryptoRuntimeException("Key not found: " + masterKeyIdentifier);
        }
        byte[] AAD = masterKeyIdentifier.getBytes(StandardCharsets.UTF_8);
        return KeyToolkit.decryptKeyLocally(wrappedKey, masterKey, AAD);
    }
}