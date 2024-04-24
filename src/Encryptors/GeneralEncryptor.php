<?php

namespace ArmCyber\Keychain\Encryptors;

use ArmCyber\Keychain\Exceptions\EncryptorException;
use ArmCyber\Keychain\Support\DataCoder;
use SensitiveParameter;
use SodiumException;

class GeneralEncryptor extends BaseEncryptor
{
    protected const PAYLOAD_PARTS_COUNT = 2;

    /**
     * Encrypt a data.
     *
     * @param mixed $data
     * @param string $encryptionKey
     * @return string
     */
    public function encrypt(#[SensitiveParameter] mixed $data, #[SensitiveParameter] string $encryptionKey): string
    {
        $dataEncoded = DataCoder::safeJsonEncode($data);
        $nonce = $this->randomBytes(SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES);
        $additionalData = $this->generateAdditionalDataUsingNonce($nonce);

        try {
            $value = sodium_crypto_aead_aes256gcm_encrypt($dataEncoded, $additionalData, $nonce, $encryptionKey);
        } catch (SodiumException $exception) {
            throw new EncryptorException('Could not encrypt the data.', previous: $exception);
        }

        return DataCoder::stringifyPayload([$nonce, $value]);
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
        [$nonce, $value] = DataCoder::parsePayload($encryptedData, self::PAYLOAD_PARTS_COUNT);
        $additionalData = $this->generateAdditionalDataUsingNonce($nonce);

        try {
            $decrypted = sodium_crypto_aead_aes256gcm_decrypt($value, $additionalData, $nonce, $decryptionKey);
        } catch (SodiumException $exception) {
            throw new EncryptorException('Could not decrypt.', previous: $exception);
        }

        if ($decrypted === false) {
            throw new EncryptorException('Could not decrypt.');
        }
        return DataCoder::safeJsonDecode($decrypted);
    }

    /**
     * Generate a new key.
     *
     * @return string
     */
    public function generateKey(): string
    {
        return sodium_crypto_aead_aes256gcm_keygen();
    }

    /**
     * Generate additional data using base64 encoded nonce.
     *
     * @param string $nonce
     * @return string
     */
    private function generateAdditionalDataUsingNonce(string $nonce): string
    {
        return substr($nonce, 4, 4);
    }
}
