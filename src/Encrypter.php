<?php

namespace Iliuxu\Encryption;

use Iliuxu\Encryption\Exceptions\DecryptException;
use Iliuxu\Encryption\Exceptions\EncryptException;
use RuntimeException;

class Encrypter
{
    /**
     * The encryption key
     *
     * @var string
     */
    protected $key;

    /**
     * The algorithm used for encryption.
     *
     * @var string
     */
    protected $cipher;

    /**
     * Create a new encrypter instance.
     *
     * @param  string $key
     * @param  string $cipher
     *
     * @throws RuntimeException
     */
    public function __construct($key, $cipher = 'AES-128-CBC')
    {
        $key = (string)$key;
        if (static::supported($key, $cipher)) {
            $this->key = $key;
            $this->cipher = $cipher;
        } else {
            throw new RuntimeException('The only supported ciphers are AES-128-CBC and AES-256-CBC with the correct key lengths.');
        }
    }

    /**
     * Determine if the given key and cipher combination is valid.
     *
     * @param  string $key
     * @param  string $cipher
     *
     * @return bool
     */
    public static function supported($key, $cipher)
    {
        $length = mb_strlen($key, '8bit');

        return ($cipher === 'AES-128-CBC' && $length === 16)
            || ($cipher === 'AES-256-CBC' && $length === 32);
    }

    /**
     * Encrypt a string without serialization.
     *
     * @param $value
     * @param $iv
     *
     * @return string
     */
    public function encryptString($value, $iv)
    {
        return $this->encrypt($value, $iv, false);
    }

    /**
     * Encrypt the given value.
     *
     * @param      $value
     * @param      $iv
     * @param bool $serialize
     *
     * @return string
     *
     * @throws EncryptException
     */
    public function encrypt($value, $iv, $serialize = true)
    {
        $iv = (string)$iv;
        $value = openssl_encrypt(
            $serialize ? serialize($value) : $value,
            $this->cipher,
            $this->key,
            0,
            $iv
        );
        if ($value === false) {
            throw  new EncryptException('Could not encrypt the data.');
        }
        return $value;
    }

    /**
     * Decrypt the given string without unserialization.
     *
     * @param $value
     * @param $iv
     *
     * @return mixed|string
     */
    public function decryptString($value, $iv)
    {
        return $this->decrypt($value, $iv, false);
    }

    /**
     * Decrypt the given value.
     *
     * @param      $value
     * @param      $iv
     * @param bool $unserialize
     *
     * @return mixed|string
     */
    public function decrypt($value, $iv, $unserialize = true)
    {
        $decrypted = openssl_decrypt(
            $value,
            $this->cipher,
            $this->key,
            0,
            $iv
        );

        if ($decrypted == false) {
            throw new DecryptException('Could not decrypt the data.');
        }

        return $unserialize ? unserialize($decrypted) : $decrypted;
    }

    /**
     * Get the encryption key.
     *
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }
}