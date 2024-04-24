<?php

namespace ArmCyber\Keychain\Encryptors;

use ArmCyber\Keychain\Exceptions\EncryptorException;
use ArmCyber\Keychain\Support\DataCoder;
use SensitiveParameter;
use SodiumException;

class PasswordEncryptor extends GeneralEncryptor
{
    /**
     * Encrypt a data.
     *
     * @param mixed $data
     * @param string $encryptionKey
     * @return string
     */
    public function encrypt(#[SensitiveParameter] mixed $data, #[SensitiveParameter] string $encryptionKey): string
    {
        $salt = $this->randomBytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $key = $this->generatePasswordHashFromPasswordAndSalt($encryptionKey, $salt);
        $value = parent::encrypt($data, $key);
        $payload = [$salt, $value];
        return DataCoder::stringifyPayload($payload);
    }

    /**
     * Decrypt the encrypted data.
     *
     * @param string $encryptedData
     * @param string $decryptionKey
     * @return mixed
     */
    public function decrypt(#[SensitiveParameter] string $encryptedData, #[SensitiveParameter] string $decryptionKey): mixed
    {
        [$salt, $value] = DataCoder::parsePayload($encryptedData);
        $key = $this->generatePasswordHashFromPasswordAndSalt($decryptionKey, $salt);
        return parent::decrypt($value, $key);
    }

    /**
     * Generate a password hash from password and salt.
     *
     * @param string $password
     * @param string $salt
     * @return string
     */
    private function generatePasswordHashFromPasswordAndSalt(string $password, string $salt): string
    {
        try {
            $key = sodium_crypto_pwhash(
                SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES,
                $password,
                $salt,
                SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
                SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE
            );
        } catch (SodiumException $exception) {
            throw new EncryptorException('Could not generate the password hash.', previous: $exception);
        }

        return $key;
    }
}
