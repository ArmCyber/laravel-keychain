<?php

namespace ArmCyber\Keychain\Encryptors;

use ArmCyber\Keychain\Exceptions\EncryptorException;
use ArmCyber\Keychain\Support\DataCoder;
use SensitiveParameter;
use SodiumException;

class PairEncryptor extends BaseEncryptor
{
    protected const PAYLOAD_PARTS_COUNT = 3;

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
        $nonce = $this->randomBytes(SODIUM_CRYPTO_BOX_NONCEBYTES);

        $tempKeys = $this->generateKeys();
        try {
            $encryptionKeyPair = sodium_crypto_box_keypair_from_secretkey_and_publickey($tempKeys['secret'], $encryptionKey);
            $value = sodium_crypto_box($dataEncoded, $nonce, $encryptionKeyPair);
        } catch (SodiumException $exception) {
            throw new EncryptorException('Could not encrypt the data.', previous: $exception);
        }

        $payload = [$nonce, $tempKeys['public'], $value];
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
        [$nonce, $publicKey, $value] = DataCoder::parsePayload($encryptedData, self::PAYLOAD_PARTS_COUNT);
        try {
            $decryptionKeyPair = sodium_crypto_box_keypair_from_secretkey_and_publickey($decryptionKey, $publicKey);
            $decrypted = sodium_crypto_box_open($value, $nonce, $decryptionKeyPair);
        } catch (SodiumException $exception) {
            throw new EncryptorException('Could not decrypt.', previous: $exception);
        }

        if ($decrypted === false) {
            throw new EncryptorException('Could not decrypt.');
        }

        return DataCoder::safeJsonDecode($decrypted);
    }

    /**
     * Generate a new public and secret keys.
     *
     * @return array{public: string, secret: string}
     */
    public function generateKeys(): array
    {
        try {
            $keyPair = sodium_crypto_box_keypair();
            $publicKey = sodium_crypto_box_publickey($keyPair);
            $secretKey = sodium_crypto_box_secretkey($keyPair);
        } catch (SodiumException $exception) {
            throw new EncryptorException('Could not generate a key pair.', previous: $exception);
        }

        return [
            'public' => $publicKey,
            'secret' => $secretKey,
        ];
    }
}
