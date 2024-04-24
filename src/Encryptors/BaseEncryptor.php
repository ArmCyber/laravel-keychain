<?php

namespace ArmCyber\Keychain\Encryptors;

use SensitiveParameter;

abstract class BaseEncryptor
{
    /**
     * Encrypt a data.
     *
     * @param mixed $data
     * @param string $encryptionKey
     * @return string
     */
    abstract public function encrypt(#[SensitiveParameter] mixed $data, #[SensitiveParameter] string $encryptionKey): string;

    /**
     * Decrypt the encrypted data.
     *
     * @param string $encryptedData
     * @param string $decryptionKey
     * @return mixed
     */
    abstract public function decrypt(#[SensitiveParameter] string $encryptedData, #[SensitiveParameter] string $decryptionKey): mixed;

    /**
     * Generate Random Bytes.
     *
     * @param int $length
     * @return string
     * @noinspection PhpDocMissingThrowsInspection
     */
    protected function randomBytes(int $length): string
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        return random_bytes($length);
    }
}
