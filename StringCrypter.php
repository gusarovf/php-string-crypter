<?php

class StringCrypter
{
    const SECRET_KEY = '';
    const SECRET_IV = '';
    const ENCRYPT_METHOD = "AES-256-CBC";

    private $key = '';
    private $iv = '';

    public function __construct()
    {
        $this->key = hash('sha256', self::SECRET_KEY);
        $this->iv = substr(hash('sha256', self::SECRET_IV), 0, 16);
    }

    public function crypt($string_to_crypt)
    {
        $output = openssl_encrypt($string_to_crypt, self::ENCRYPT_METHOD, $this->key, 0, $this->iv);
        return base64_encode($output);
    }

    public function decrypt($string_to_decrypt)
    {
        return openssl_decrypt(base64_decode($string_to_decrypt), self::ENCRYPT_METHOD, $this->key, 0, $this->iv);
    }

}