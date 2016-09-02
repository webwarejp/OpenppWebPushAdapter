<?php

namespace Openpp\WebPushAdapter\Adapter;

use Sly\NotificationPusher\Adapter\BaseAdapter;
use Sly\NotificationPusher\Model\PushInterface;
use Sly\NotificationPusher\Exception\PushException;
use Sly\NotificationPusher\Exception\AdapterException;
use Sly\NotificationPusher\Collection\DeviceCollection;
use Base64Url\Base64Url;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use JDR\JWS\ECDSA\ES256;
use Openpp\WebPushAdapter\Encryptor\MessageEncryptor;
use Openpp\WebPushAdapter\Util\PublicKeyUtil;
use Sly\NotificationPusher\Model\Message;


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

        $ecdsaCryptoKey = $this->getECDSACryptoKey();
        $orign     = null;
        $token     = null;

        $message = $this->createMessageBody($push->getMessage());

        foreach ($push->getDevices() as $device) {
            $endPoint  = $device->getToken();

            $newOrigin = $this->getOrigin($endPoint);
            if (is_null($token) || $orign != $newOrigin) {
                $origin = $newOrigin;
                $token = $this->createSignatureToken($origin);
            }

            $headers = $client->getRequest()->getHeaders();
            $headers
                ->addHeaderLine('Crypto-Key', 'p256ecdsa="' . $ecdsaCryptoKey . '"')
                ->addHeaderLine('Authorization', 'Bearer ' . $token)
            ;

            if (!empty($message)
                && !empty($device->getParameter('publicKey'))
                && !empty($device->getParameter('authToken'))
            ) {
                $encryptor = $this->getMessageEncryptor();
                $body = $encryptor->encrypt(
                    $message,
                    $device->getParameter('publicKey'),
                    $device->getParameter('authToken')
                );

                $headers
                    ->addHeaderLine('Content-Encoding', 'aesgcm')
                    ->addHeaderLine('Encryption', 'keyid="p256dh";salt="' .$encryptor->getSalt() .'"')
                ;
                $cryptoKeyHead = $headers->get('Crypto-Key');
                $cryptoKeyValue = 'keyid="p256dh";dh="'. $encryptor->getServerPublicKey() .'"' . ';' . $cryptoKeyHead->getFieldValue();
                $headers->addHeaderLine('Crypto-Key', $cryptoKeyValue);

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

            switch ($this->response->getStatusCode()) {
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
                    // TODO: FCM returns 400 on sending to the unsubscribed endpoint.
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
     * Create message body.
     *
     * @param Message $message
     */
    protected function createMessageBody(Message $message)
    {
        $body = $message->getOptions();
        $body['message'] = $message->getText();

        return json_encode($body);
    }

    /**
     * Get the message encryptor.
     *
     * @return \Openpp\WebPusherAdapter\Encrytptor\MessageEncryptor
     */
    protected function getMessageEncryptor()
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
    protected function getECDSACryptoKey()
    {
        return Base64Url::encode(PublicKeyUtil::getKeyFromPem($this->getParameter('publicKey')));
    }

    /**
     *  Get the origin (Section 6.1 of [RFC6454]) of the push resource URL.
     *
     * @param string $endPoint
     *
     * @return string
     */
    protected function getOrigin($endPoint)
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
    protected function createSignatureToken($origin, \DateTime $expiration = null)
    {
        if (is_null($expiration)) {
            $expiration = new \DateTime('+ 1 hours');
        }

        $signer = new ES256();
        $privateKey = new Key('file://' . $this->getParameter('privateKey'));

        $builder = new Builder();
        $token = $builder
            ->setAudience($origin)
            ->setExpiration($expiration->getTimestamp())
            ->sign($signer, $privateKey)
            ->getToken();

        return $token;
    }
}