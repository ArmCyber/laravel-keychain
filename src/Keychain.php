<?php

namespace ArmCyber\Keychain;

use ArmCyber\Keychain\Encryptors\GeneralEncryptor;
use ArmCyber\Keychain\Encryptors\PairEncryptor;
use ArmCyber\Keychain\Encryptors\PasswordEncryptor;
use ArmCyber\Keychain\Exceptions\EncryptorException;
use ArmCyber\Keychain\Exceptions\InvalidCredentialException;
use ArmCyber\Keychain\Exceptions\InvalidKeychainPasswordException;
use ArmCyber\Keychain\Exceptions\KeychainKeyAccessForbiddenException;
use ArmCyber\Keychain\Exceptions\KeychainLockedException;
use ArmCyber\Keychain\Support\DataCoder;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Str;
use RuntimeException;
use SensitiveParameter;
use SensitiveParameterValue;

final class Keychain
{
    private const INTERNAL_KEYS_COUNT = 3;
    private const INTERNAL_KEY_UUID = 0;
    private const INTERNAL_KEY_GENERAL = 1;
    private const INTERNAL_KEY_PAIR_PUBLIC = 2;

    /**
     * Keeps the instance of the keychain with current credentials.
     *
     * @var Keychain
     */
    private static self $currentKeychainInstance;

    /**
     * Keychain UUID
     *
     * @var string
     */
    private readonly string $uuid;

    /**
     * If keys can be retrieved.
     *
     * @var bool
     */
    private readonly bool $canRetrieveKeys;

    /**
     * The GeneralEncryptor dependency.
     *
     * @var GeneralEncryptor
     */
    private readonly GeneralEncryptor $generalEncryptor;

    /**
     * The PairEncryptor dependency.
     *
     * @var PairEncryptor
     */
    private readonly PairEncryptor $pairEncryptor;

    /**
     * The PasswordEncryptor dependency.
     *
     * @var PasswordEncryptor
     */
    private readonly PasswordEncryptor $passwordEncryptor;

    /**
     * Keychain credentials.
     *
     * @var SensitiveParameterValue
     */
    private readonly SensitiveParameterValue $credentials;

    /**
     * Keychain pair secret key.
     *
     * @var SensitiveParameterValue
     */
    private readonly SensitiveParameterValue $pairSecretKey;

    /**
     * Constructor.
     *
     * @param array $credentials
     * @param string|null $pairSecretKey
     */
    private function __construct(#[SensitiveParameter] array $credentials, #[SensitiveParameter] ?string $pairSecretKey = null)
    {
        $this->credentials = new SensitiveParameterValue($credentials);
        $this->uuid = DataCoder::decompressUuid($this->getInternalKey(self::INTERNAL_KEY_UUID));

        if ($pairSecretKey !== null) {
            $this->fillPairSecretKey($pairSecretKey);
            $this->canRetrieveKeys = true;
        } else {
            $this->canRetrieveKeys = false;
        }

        $this->generalEncryptor = App::make(GeneralEncryptor::class);
        $this->pairEncryptor = App::make(PairEncryptor::class);
        $this->passwordEncryptor = App::make(PasswordEncryptor::class);
    }

    /**
     * Check if the Keychain is unlocked.
     *
     * @return bool
     */
    public function isUnlocked(): bool
    {
        return isset($this->pairSecretKey);
    }

    /**
     * Unlock the Keychain.
     *
     * @param $password
     * @param $token
     * @return void
     */
    public function unlock(#[SensitiveParameter] $password, #[SensitiveParameter] $token): void
    {
        if ($this->isUnlocked()) {
            return;
        }

        $generalKey = $this->getInternalKey(self::INTERNAL_KEY_GENERAL);
        $encryptedSecretKey = $this->generalEncryptor->decrypt($token, $generalKey);

        try {
            $encodedSecretKey = $this->passwordEncryptor->decrypt($encryptedSecretKey, $password);
        } catch (EncryptorException) {
            throw new InvalidKeychainPasswordException('The Keychain password is invalid.');
        }

        $secretKey = DataCoder::trimmedBase64Decode($encodedSecretKey);
        $this->fillPairSecretKey($secretKey);
    }

    /**
     * Unlock the Keychain using the master key.
     *
     * @param $masterKey
     * @return void
     */
    public function unlockUsingMasterKey(#[SensitiveParameter] $masterKey): void
    {
        if ($this->isUnlocked()) {
            return;
        }

        $secretKey = DataCoder::trimmedBase64Decode($masterKey);
        $this->fillPairSecretKey($secretKey);
    }

    /**
     * Encrypt the credential.
     *
     * @param mixed $data
     * @return string
     */
    public function encryptCredential(#[SensitiveParameter] mixed $data): string
    {
        $pairPublicKey = $this->getInternalKey(self::INTERNAL_KEY_PAIR_PUBLIC);
        $pairEncryptedData = $this->pairEncryptor->encrypt($data, $pairPublicKey);

        $generalKey = $this->getInternalKey(self::INTERNAL_KEY_GENERAL);
        return $this->generalEncryptor->encrypt($pairEncryptedData, $generalKey);
    }

    /**
     * Decrypt the credential.
     *
     * @param string $encryptedData
     * @return mixed
     */
    public function decryptCredential(#[SensitiveParameter] string $encryptedData): mixed
    {
        $pairSecretKey = $this->getPairSecretKey();
        $generalKey = $this->getInternalKey(self::INTERNAL_KEY_GENERAL);

        $pairEncryptedData = $this->generalEncryptor->decrypt($encryptedData, $generalKey);
        return $this->pairEncryptor->decrypt($pairEncryptedData, $pairSecretKey);
    }

    /**
     * Generate a new Keychain password and token.
     *
     * @return array{password: string, token: string}
     */
    public function generateKeychainPasswordAndToken(): array
    {
        $this->verifyKeychainUnlocked();
        $password = Str::password();
        $secretKey = $this->getPairSecretKey();
        $encodedSecretKey = DataCoder::trimmedBase64Encode($secretKey);
        $encryptedSecretKey = $this->passwordEncryptor->encrypt($encodedSecretKey, $password);
        $generalKey = $this->getInternalKey(self::INTERNAL_KEY_GENERAL);
        $token = $this->generalEncryptor->encrypt($encryptedSecretKey, $generalKey);
        return [
            'password' => $password,
            'token' => $token,
        ];
    }

    /**
     * Get the Keychain UUID.
     *
     * @return string
     */
    public function getUUID(): string
    {
        return $this->uuid;
    }

    /**
     * Get the Keychain Key.
     *
     * @return string
     * @throws KeychainKeyAccessForbiddenException
     */
    public function getKeychainKey(): string
    {
        $this->verifyCanRetrieveKeys();
        $credentials = $this->credentials->getValue();
        return DataCoder::stringifyPayload($credentials);
    }

    /**
     * Get the master key.
     *
     * @return string
     * @throws KeychainKeyAccessForbiddenException
     */
    public function getMasterKey(): string
    {
        $this->verifyCanRetrieveKeys();
        $pairSecretKey = $this->getPairSecretKey();
        return DataCoder::trimmedBase64Encode($pairSecretKey);
    }

    /**
     * Retrieve an internal key.
     *
     * @param int $key
     * @return string
     */
    private function getInternalKey(int $key): string
    {
        $credentials = $this->credentials->getValue();
        if (!array_key_exists($key, $credentials)) {
            throw new RuntimeException('Internal key is not defined.');
        }
        return $credentials[$key];
    }

    /**
     * Get the pair secret key
     *
     * @return string
     */
    private function getPairSecretKey(): string
    {
        $this->verifyKeychainUnlocked();
        return $this->pairSecretKey->getValue();
    }

    /**
     * Fill the pair secret key.
     *
     * @param string $pairSecretKey
     * @return void
     */
    private function fillPairSecretKey(#[SensitiveParameter] string $pairSecretKey): void
    {
        $this->verifyPairSecretKey($pairSecretKey);
        $this->pairSecretKey = new SensitiveParameterValue($pairSecretKey);
    }

    /**
     * Verify that the pair secret key is valid
     *
     * @param string $pairSecretKey
     * @return void
     */
    private function verifyPairSecretKey(#[SensitiveParameter] string $pairSecretKey): void
    {
        /** @var PairEncryptor $pairEncryptor */
        $pairEncryptor = App::make(PairEncryptor::class);
        $verifier = Str::random();
        $pairPublicKey = $this->getInternalKey(self::INTERNAL_KEY_PAIR_PUBLIC);
        $encryptedString = $pairEncryptor->encrypt($verifier, $pairPublicKey);
        $decryptedString = $pairEncryptor->decrypt($encryptedString, $pairSecretKey);
        if ($verifier !== $decryptedString) {
            throw new InvalidCredentialException('Pair secret key is invalid.');
        }
    }

    /**
     * Verify that the Keychain is unlocked.
     *
     * @return void
     */
    private function verifyKeychainUnlocked(): void
    {
        if (!$this->isUnlocked()) {
            throw new KeychainLockedException('Keychain is locked.');
        }
    }

    /**
     * Verifies if keys can be retrieved.
     *
     * @return void
     * @throws KeychainKeyAccessForbiddenException
     */
    private function verifyCanRetrieveKeys(): void
    {
        if (!$this->canRetrieveKeys) {
            throw new KeychainKeyAccessForbiddenException('Access to keychain keys is denied.');
        }
    }

    /**
     * Get the Keychain instance with current internal keys.
     *
     * @return self
     */
    public static function current(): self
    {
        if (!isset(self::$currentKeychainInstance)) {
            $credentials = self::tryGetCurrentInternalKeys();
            if ($credentials === null) {
                throw new InvalidCredentialException('Keychain key is invalid.');
            }
            self::$currentKeychainInstance = new self($credentials);
        }

        return self::$currentKeychainInstance;
    }

    /**
     * Create a new Keychain instance with new internal keys.
     *
     * @return self
     */
    public static function generate(): self
    {
        $uuidBinary = DataCoder::compressUuid(Str::uuid());

        /** @var GeneralEncryptor $generalEncryptor */
        $generalEncryptor = App::make(GeneralEncryptor::class);
        $generalKey = $generalEncryptor->generateKey();

        /** @var PairEncryptor $pairEncryptor */
        $pairEncryptor = App::make(PairEncryptor::class);
        $pairKeys = $pairEncryptor->generateKeys();

        $credentials = [
            self::INTERNAL_KEY_UUID => $uuidBinary,
            self::INTERNAL_KEY_GENERAL => $generalKey,
            self::INTERNAL_KEY_PAIR_PUBLIC => $pairKeys['public'],
        ];

        return new self($credentials, $pairKeys['secret']);
    }

    /**
     * Try to get current internal keys.
     *
     * @return array|null
     */
    private static function tryGetCurrentInternalKeys(): ?array
    {
        $keychainKey = config('keychain.key');

        if ($keychainKey === null) {
            return null;
        }

        $tokenData = DataCoder::parsePayload($keychainKey, self::INTERNAL_KEYS_COUNT);
        if (array_values($tokenData) === $tokenData) {
            return $tokenData;
        }

        return null;
    }
}
