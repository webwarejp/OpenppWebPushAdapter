<?php

namespace Openpp\WebPushAdapter\Util;

use Mdanter\Ecc\Serializer\PublicKey\DerPublicKeySerializer;
use Mdanter\Ecc\Serializer\PublicKey\PemPublicKeySerializer;

class PublicKeyUtil
{
    /**
     * Get the public key from pem which includes a point on the P-256 elliptic curve [FIPS-186-3],
     * encoded in the uncompressed form described in [X9.62] Annex A
     * (that is, 65 octets, starting with an 0x04 octet).
     *
     * @param string $path
     *
     * @return string|false
     */
    public static function getKeyFromPem($path)
    {
        $content = file_get_contents($path);

        $decSerializer = new DerPublicKeySerializer();
        $pemSerializer = new PemPublicKeySerializer($decSerializer);
        $key = $pemSerializer->parse($content);
        $key = $decSerializer->getUncompressedKey($key);

        return hex2bin($key);
    }
}
