<?php

namespace Openpp\WebPusherAdapter\Encrytptor;

use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Serializer\Point\UncompressedPointSerializer;
use Mdanter\Ecc\Curves\CurveFactory;
use Mdanter\Ecc\Curves\NistCurve;
use Base64Url\Base64Url;
use Mdanter\Ecc\Crypto\Key\PublicKey;

class MessageEncryptor
{
    /*
     * The push service may not support more than 4096 octets of payload body,
     * which equates to 4077 octets of cleartext.
     */
    const MAX_MESSAGE_LENGTH = 4076;

    const HMAC_ALGO = 'sha256';

    /**
     * @var \Mdanter\Ecc\Crypto\Key\PublicKey
     */
    protected $publicKey;

    /**
     * @var \Mdanter\Ecc\Crypto\Key\PrivateKey
     */
    protected $privateKey;

    /**
     * @var string
     */
    protected $salt;

    /**
     * @var string
     */
    protected $publicKeyContent;

    /**
     * @var \Mdanter\Ecc\Primitives\GeneratorPoint
     */
    protected $generator;

    /**
     * @var \Mdanter\Ecc\Primitives\CurveFpInterface
     */
    protected $curve;

    /**
     * @var \Mdanter\Ecc\Math\GmpMathInterface
     */
    protected $adapter;

    /**
     * @var \Mdanter\Ecc\Serializer\Point\PointSerializerInterface
     */
    protected $serializer;

    /**
     * Constructor
     */
    public function __construct()
    {
        $this->generator  = CurveFactory::getGeneratorByName(NistCurve::NAME_P256);
        $this->curve      = CurveFactory::getCurveByName(NistCurve::NAME_P256);
        $this->adapter    = EccFactory::getAdapter();
        $this->serializer = new UncompressedPointSerializer($this->adapter);

        $this->initialize();
    }

    /**
     * Generate key pare and salt.
     */
    public function initialize()
    {
        // generate key pair.
        $this->privateKey = $this->generator->createPrivateKey();
        $this->publicKey  = $this->privateKey->getPublicKey();

        // generate salt
        $this->salt = openssl_random_pseudo_bytes(16);

        $this->publicKeyContent = hex2bin($this->serializer->serialize($this->publicKey->getPoint()));
    }

    /**
     * @return string
     */
    public function getServerPublicKey($raw = false)
    {
        if ($raw) {
            return $this->publicKeyContent;
        }

        return Base64Url::encode($this->publicKeyContent);
    }

    /**
     * @return string
     */
    public function getSalt($raw = false)
    {
        if ($raw) {
            return $this->salt;
        }

        return Base64Url::encode($this->salt);
    }

    /**
     * Encrypt the message for Web Push.
     *
     * @param string  $message
     * @param string  $userPublicKey
     * @param string  $userAuthToken
     * @param boolean $regenerateKeys
     *
     * @return string
     */
    public function encrypt($message, $userPublicKey,  $userAuthToken, $regenerateKeys = false)
    {
        if (self::MAX_MESSAGE_LENGTH < strlen($message)) {
            throw new \RuntimeException(sprintf(
                'Length of message must not be greater than %d octets.', self::MAX_MESSAGE_LENGTH
            ));
        }

        if ($regenerateKeys) {
            $this->initialize();
        }

        // get shared secret
        $sharedSecret = $this->getSharedSecret($userPublicKey);

        $ikm = !empty($userAuthToken) ?
            self::hkdf($userAuthToken, $sharedSecret, 'Content-Encoding: auth'.chr(0), 32) :
            $sharedSecret;

        $context = $this->createContext($userPublicKey);

        // derive the Content Encryption Key
        $contentEncryptionKey = self::hkdf($this->salt, $ikm, self::createInfo('aesgcm128', $context), 16);

        // derive nonce
        $nonce = self::hkdf($this->salt, $ikm, self::createInfo('nonce', $context), 12);

        list($encryptedText, $tag) = \AESGCM\AESGCM::encrypt($contentEncryptionKey, $nonce, $message, "");

        return $encryptedText . $tag;
    }

    /**
     * Get shared secret from user public key and server private key.
     *
     * @param string $userPublicKey
     *
     * @return string
     */
    private function getSharedSecret($userPublicKey)
    {
        $userPublicKeyPoint = $this->serializer->unserialize($this->curve, bin2hex($userPublicKey));
        $userPublicKeyObject = $this->generator->getPublicKeyFrom(
            $userPublicKeyPoint->getX(),
            $userPublicKeyPoint->getY(),
            $this->generator->getOrder()
        );

        $point = $userPublicKeyObject->getPoint()->mul($this->privateKey->getSecret())->getX();

        return hex2bin($this->adapter->decHex((string)$point));
    }

    /**
     * HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
     *
     * This is used to derive a secure encryption key from a mostly-secure shared
     * secret.
     *
     * This is a partial implementation of HKDF tailored to our specific purposes.
     * In particular, for us the value of N will always be 1, and thus T always
     * equals HMAC-Hash(PRK, info | 0x01).
     *
     * See {@link https://www.rfc-editor.org/rfc/rfc5869.txt}
     * From {@link https://github.com/GoogleChrome/push-encryption-node/blob/master/src/encrypt.js}
     *
     * @param string $salt A non-secret random value
     * @param string $ikm  Input keying material
     * @param string $info  Application-specific context
     * @param intger $length  The length (in bytes) of the required output key
     *
     * @return string
     */
    private static function hkdf($salt, $ikm, $info, $length)
    {
        // extract
        $prkHmac = hash_hmac(self::HMAC_ALGO, $ikm, $salt, true);
        // expand
        $infoHmac = hash_hmac(self::HMAC_ALGO, $info . chr(1), $prkHmac, true);

        return substr($infoHmac, 0, $length);
    }

    /**
     * context = label || 0x00 ||
     *           length(recipient_public) || recipient_public ||
     *           length(sender_public) || sender_public
     *
     * @param string $userPublicKey
     *
     * @return string
     */
    private function createContext($userPublicKey)
    {
        $label = 'P-256';
        // The two length fields are encoded as a two octet unsigned integer in network byte order.
        $recipientPublicLength = chr(0) . chr(strlen($userPublicKey));
        $senderPublicLength = chr(0) . chr(strlrn($this->publicKeyContent));

        return $label . chr(0) . $recipientPublicLength . $userPublicKey . $senderPublicLength . $this->publicKeyContent;
    }

    /**
     * info = "Content-Encoding: $type" || 0x00 || context
     *
     * @param string $type
     * @param string $context
     *
     * @return string
     */
    private static function createInfo($type, $context)
    {
        return 'Content-Encoding: ' . $type . chr(0). $context;
    }
}