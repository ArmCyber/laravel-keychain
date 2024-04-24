<?php

namespace ArmCyber\Keychain\Support;

use ArmCyber\Keychain\Exceptions\EncoderException;
use Illuminate\Support\Str;
use SensitiveParameter;

class DataCoder
{
    /**
     * Encode the string to trimmed base64.
     *
     * @param string $string
     * @return string
     */
    public static function trimmedBase64Encode(#[SensitiveParameter] string $string): string
    {
        $base64String = base64_encode($string);

        return Str::of($base64String)->replace(['+', '/'], ['-', '_'])->rtrim('=')->value();
    }

    /**
     * Decode the trimmed base64 string.
     *
     * @param string $encodedString
     * @return string
     */
    public static function trimmedBase64Decode(#[SensitiveParameter] string $encodedString): string
    {
        $base64String = Str::replace(['-', '_'], ['+', '/'], $encodedString);

        $remainder = strlen($base64String) % 4;
        if ($remainder !== 0) {
            $base64String .= Str::repeat('=', 4 - $remainder);
        }

        $result = base64_decode($base64String, true);

        if ($result === false) {
            throw new EncoderException('Invalid base64 string.');
        }

        return $result;
    }

    /**
     * Safely encode the data to JSON format.
     *
     * @param mixed $data
     * @return string
     */
    public static function safeJsonEncode(#[SensitiveParameter] mixed $data): string
    {
        $json = json_encode($data);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new EncoderException('Cannot encode the data to JSON, reason: ' . json_last_error_msg());
        }

        return $json;
    }

    /**
     * Safely decode the JSON data.
     *
     * @param string $encodedData
     * @return mixed
     */
    public static function safeJsonDecode(#[SensitiveParameter] string $encodedData): mixed
    {
        $result = json_decode($encodedData, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new EncoderException('Cannot decode the JSON data, reason: ' . json_last_error_msg());
        }

        return $result;
    }

    /**
     * Stringify the binary payload.
     *
     * @param array $payload
     * @param string $separator
     * @return string
     */
    public static function stringifyPayload(#[SensitiveParameter] array $payload, string $separator = '.'): string
    {
        $encodedPayload = self::mapSensitiveArray($payload, fn(#[SensitiveParameter] $x) => self::trimmedBase64Encode($x));

        return implode($separator, $encodedPayload);
    }

    /**
     * Parse the binary payload.
     *
     * @param string $token
     * @param int|null $partsCount
     * @param string $separator
     * @return array
     */
    public static function parsePayload(#[SensitiveParameter] string $token, ?int $partsCount = null, string $separator = '.'): array
    {
        $parts = explode($separator, $token);
        if ($partsCount !== null && count($parts) !== $partsCount) {
            throw new EncoderException('Invalid payload.');
        }

        return self::mapSensitiveArray($parts, fn(#[SensitiveParameter] $x) => self::trimmedBase64Decode($x));
    }

    /**
     * Compress the UUID string.
     *
     * @param string $uuid
     * @return string
     */
    public static function compressUuid(string $uuid): string
    {
        $uuidBinary = false;

        if (Str::isUuid($uuid)) {
            $uuidBinary = hex2bin(str_replace('-', '', $uuid));
        }

        if ($uuidBinary === false) {
            throw new EncoderException('Invalid UUID string.');
        }

        return $uuidBinary;
    }

    /**
     * Decompress the UUID binary.
     *
     * @param string $uuidBinary
     * @return string
     */
    public static function decompressUuid(string $uuidBinary): string
    {
        $uuid = false;

        $decompressedUuid = bin2hex($uuidBinary);
        if (strlen($decompressedUuid) === 32) {
            $maybeUuid = substr($decompressedUuid, 0, 8) . '-' .
                substr($decompressedUuid, 8, 4) . '-' .
                substr($decompressedUuid, 12, 4) . '-' .
                substr($decompressedUuid, 16, 4) . '-' .
                substr($decompressedUuid, 20);
            if (Str::isUuid($maybeUuid)) {
                $uuid = $maybeUuid;
            }
        }

        if ($uuid === false) {
            throw new EncoderException('Invalid UUID binary.');
        }

        return $uuid;
    }

    /**
     * Map a sensitive array
     *
     * @param array $array
     * @param callable $callback
     * @return array
     */
    private static function mapSensitiveArray(#[SensitiveParameter] array $array, callable $callback): array
    {
        $result = [];

        foreach ($array as $key => $value) {
            $result[$key] = $callback($value);
        }

        return $result;
    }
}
