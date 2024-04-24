<?php

namespace ArmCyber\Keychain\Exceptions;

use RuntimeException;
use Throwable;

class EncryptorException extends RuntimeException
{
    /**
     * Constructor.
     *
     * @param string $message The error message.
     * @param Throwable|null $previous The previous exception.
     */
    public function __construct(string $message, ?Throwable $previous = null)
    {
        if ($previous !== null) {
            $previousMessage = $previous->getMessage();
            $message .= " Previous message: $previousMessage.";
        }

        parent::__construct($message, 0, $previous);
    }

    /**
     * Set the exception message.
     *
     * @param string $message
     * @return void
     */
    public function setMessage(string $message): void
    {
        $this->message = $message;
    }
}
