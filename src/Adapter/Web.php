<?php

namespace Openpp\WebPushAdapter\Adapter;

use Sly\NotificationPusher\Adapter\BaseAdapter;
use Sly\NotificationPusher\Exception\PushException;
use Sly\NotificationPusher\Exception\AdapterException;
use Base64Url\Base64Url;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use JDR\JWS\ECDSA\ES256;
use Openpp\WebPusherAdapter\Encrytptor\MessageEncryptor;

/**
 * Web Push (VAPID) Adapter for sly/notification-pusher
 *
 */
class Web extends BaseAdapter
{
    /**
     * @var \Zend\Http\Client
     */
    private $openedClient;

    /**
     * @var MessageEncryptor
     */
    private $messageEncryptor;

    /**
     * {@inheritdoc}
     *
     * @throws \Sly\NotificationPusher\Exception\AdapterException
     */
    public function __construct(array $parameters = array())
    {
        parent::__construct($parameters);

        foreach (array('publicKey', 'privateKey') as $keyName) {
            $key = $this->getParameter($keyName);

            if (false === file_exists($key)) {
                throw new AdapterException(sprintf('%s %s does not exist', $keyName, $privateKey));
            }
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getDefinedParameters()
    {
        return array();
    }

    /**
     * {@inheritdoc}
     */
    public function getDefaultParameters()
    {
        return array(
            'ttl' => 86400, // 1 day
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getRequiredParameters()
    {
        return array(
            'publicKey',
            'privateKey',
        );
    }

    /**
     * {@inheritdoc}
     */
    public function supports($token)
    {
        return is_string($token) && $token != '';
    }

    /**
     * {@inheritdoc}
     *
     * @throws \Sly\NotificationPusher\Exception\PushException
     */
    public function push(PushInterface $push)
    {
        $client        = $this->getOpenedClient();
        $pushedDevices = new DeviceCollection();

        $cryptoKey = $this->getCryptoKey();
        $orign     = null;
        $token     = null;

        $hasMessage = false;
        if ($push->getMessage()->getText()) {
            $encryptor = $this->getMessageEncryptor();
            $hasMessage = true;
        }

        foreach ($push->getDevices() as $device) {
            $endPoint  = $device->getToken();

            $newOrigin = $this->getOrigin($endPoint);
            if (is_null($token) || $orign != $newOrigin) {
                $origin = $newOrigin;
                $token = $this->createSignatureToken($endPoint);
            }

            $headers = $client->getRequest()->getHeaders();
            $headers
                ->addHeaderLine('Crypto-Key', 'p256ecdsa=' . $cryptoKey)
                ->addHeaderLine('Authorization', 'WebPush ' . $token)
            ;

            if ($hasMessage) {
                $body = $encryptor->encrypt(
                    $push->getMessage()->getText(),
                    $device->getPublicKey(),
                    $device->getAuthToken()
                );

                $headers
                    ->addHeaderLine('Content-Encoding', 'aesgcm128')
                    ->addHeaderLine('Encryption', 'keyid="p256dh";salt="' .$encryptor->getSalt() .'"')
                ;
                $cryptoKey = $headers->get('Crypto-Key');
                $cryptoKey .= ';keyid="p256dh";dh="'. $encryptor->getServerPublicKey() .'"';
                $headers->addHeaderLine('Crypto-Key', $cryptoKey);

                $encType = 'application/octet-stream';
            } else {
                $body = '';
                $encType = null;
            }

            $headers->addHeaderLine('TTL', $push->getMessage()->getOption('ttl', $this->getParameter('ttl')));

            if ($push->getMessage()->hasOption('urgency')) {
                $headers->addHeaderLine('Urgency', $push->getMessage()->getOption('urgency'));
            }
            if ($push->getMessage()->hasOption('topic')) {
                $headers->addHeaderLine('Topic', $push->getMessage()->getOption('topic'));
            }

            $this->response = $client->setUri($endPoint)
                                     ->setHeaders($headers)
                                     ->setMethod('POST')
                                     ->setRawBody($body)
                                     ->setEncType($encType)
                                     ->send();

            switch ($response->getStatusCode()) {
                case 500:
                    throw new PushException('500 Internal Server Error');
                    break;
                case 503:
                    $exceptionMessage = '503 Server Unavailable';
                    if ($retry = $response->getHeaders()->get('Retry-After')) {
                         $exceptionMessage .= '; Retry After: ' . $retry;
                    }
                    throw new PushException($exceptionMessage);
                    break;
                case 401:
                    throw new PushException('401 Forbidden; Authentication Error');
                    break;
                case 400:
                    throw new PushException('400 Bad Request; invalid message');
                    break;
            }

            $pushedDevices->add($device);
        }

        return $pushedDevices;
    }

    /**
     * Get opened client.
     *
     * @return \Zend\Http\Client
     */
    public function getOpenedClient()
    {
        if (!isset($this->openedClient)) {
            $this->openedClient = new \Zend\Http\Client(
                null, array(
                    'adapter' => 'Zend\Http\Client\Adapter\Socket',
                    'sslverifypeer' => false
                )
            );
        }

        return $this->openedClient;
    }

    /**
     * Get message encryptor.
     *
     * @return \Openpp\WebPusherAdapter\Encrytptor\MessageEncryptor
     */
    private function getMessageEncryptor()
    {
        if (!isset($this->messageEncryptor)) {
            $this->messageEncryptor = new MessageEncryptor();
        }

        return $this->messageEncryptor;
    }

    /**
     * Get the ECDSA public key encoded by the URL- and filename-safe variant of
     * base-64 [RFC4648] with padding removed.
     */
    private function getCryptoKey()
    {
        $publicKey = new Key($this->getParameter('publicKey'));

        return Base64Url::encode($publicKey->getContent());
    }

    /**
     *  Get the origin (Section 6.1 of [RFC6454]) of the push resource URL.
     *
     * @param string $endpoint
     *
     * @return string
     */
    private function getOrigin($endpoint)
    {
        $url = parse_url($endPoint);
        $origin = $url['scheme'] . '://' . $url['host'];
        if (isset($url['port'])) {
            $origin = $orign . ':' . $url['port'];
        }

        return $origin;
    }

    /**
     * Create the JWT signed by using ES256.
     *
     * @param string $origin
     * @param \DateTime $expiration
     * @param string $subject
     *
     * @return Token
     */
    private function createSignatureToken($origin, \DateTime $expiration = null)
    {
        if (is_null($expiration)) {
            $expiration = new \DateTime('+ 24 hours');
        }

        $signer = new ES256();
        $privateKey = new Key($this->getParameter('privateKey'));

        $builder = new Builder();
        $token = $builder
            ->setAudience($origin)
            ->setExpiration($expiration->getTimestamp())
            ->sign($signer, $privateKey)
            ->getToken();

        return $token;
    }
}