<?php
require '../src/Encrypter.php';

try {
    $a = new \Iliuxu\Encryption\Encrypter(md5(time()), 'AES-256-CBC');
    $iv = substr(md5(time()), 0, 16);
    $value = '1234567823456345674567456745674567456745645674564r54r5t6456';
    var_dump($value);
    var_dump($iv);
    $en = $a->encrypt($value, $iv);
    var_dump($en);
    var_dump($a->decrypt($en, $iv));
    $en = $a->encryptString($value, $iv);
    var_dump($en);
    var_dump($a->decryptString($en, $iv));
} catch (Exception  $e) {
    echo $e->getMessage();
}