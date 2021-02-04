<?php

namespace League\OAuth2\Client\Token;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use GuzzleHttp\ClientInterface;
use InvalidArgumentException;

class AppleAccessToken extends AccessToken
{

    /**
     * Default apcu cache key to store the apple keys
     */
    const APCU_DEFAULT_KEY = 'applekeys';

    /**
     * Default apcu ttl, in seconds, to store the apple keys
     */
    const APCU_DEFAULT_TTL = 300;

    /**
     * @var string
     */
    protected $idToken;

    /**
     * @var string
     */
    protected $email;

    /**
     * @var boolean
     */
    protected $isPrivateEmail;

    /**
     * @var string|null
     */
    protected $apcu_key = null;

    /**
     * @var int|null
     */
    protected $apcu_ttl = null;

    /**
     * @var bool
     */
    protected $apcu_enabled = false;

    /**
     * @var ClientInterface
     */
    protected $httpClient;


    /**
     * Constructs an access token.
     *
     * @param ClientInterface $httpClient the http client to use
     * @param array $options An array of options returned by the service provider
     *     in the access token request. The `access_token` option is required.
     * @throws InvalidArgumentException if `access_token` is not provided in `$options`.
     *
     * @throws \Exception
     */
    public function __construct($httpClient, array $options = [])
    {
        $this->apcu_key = self::APCU_DEFAULT_KEY;
        $this->apcu_ttl = self::APCU_DEFAULT_TTL;

        $this->apcu_enabled = function_exists('apcu_store') && function_exists('apcu_fetch');

        if (empty($options['access_token'])) {
            throw new InvalidArgumentException('Required option not passed: "access_token"');
        }

        $this->httpClient = $httpClient;

        if (array_key_exists('refresh_token', $options)) {
            if (empty($options['id_token'])) {
                throw new InvalidArgumentException('Required option not passed: "id_token"');
            }

            $decoded = null;
            $keys = $this->getAppleKey();
            $last = end($keys);
            foreach ($keys as $key) {
                try {
                    $decoded = JWT::decode($options['id_token'], $key, ['RS256']);
                    break;
                } catch (\Exception $exception) {
                    if ($last === $key) {
                        throw $exception;
                    }
                }
            }
            if (null === $decoded) {
                throw new \Exception('Got no data within "id_token"!');
            }
            $payload = json_decode(json_encode($decoded), true);

            $options['resource_owner_id'] = $payload['sub'];

            if (isset($payload['email_verified']) && $payload['email_verified']) {
                $options['email'] = $payload['email'];
            }

            if (isset($payload['is_private_email'])) {
                $this->isPrivateEmail = $payload['is_private_email'];
            }
        }

        parent::__construct($options);

        if (isset($options['id_token'])) {
            $this->idToken = $options['id_token'];
        }

        if (isset($options['email'])) {
            $this->email = $options['email'];
        }
    }

    /**
     * @return array Apple's JSON Web Key
     */
    protected function getAppleKey()
    {
        $appleKeys = null;

        if ($this->apcu_enabled) {
            $appleKeys = apcu_fetch($this->apcu_key);
        }

        if (empty($appleKeys)) {
            $response = $this->httpClient->request('GET', 'https://appleid.apple.com/auth/keys');

            if ($response) {
                if ($this->apcu_enabled) {
                    apcu_store($this->apcu_key, $appleKeys, $this->apcu_ttl);
                }

                return JWK::parseKeySet(json_decode($response->getBody()->getContents(), true));
            }
        }

        return [];
    }

    /**
     * @return string
     */
    public function getIdToken()
    {
        return $this->idToken;
    }

    /**
     * @return string
     */
    public function getEmail()
    {
        return $this->email;
    }

    /**
     * @return boolean
     */
    public function isPrivateEmail()
    {
        return $this->isPrivateEmail;
    }

    /**
     * @param string $cacheKey
     */
    public function setCacheKey($cacheKey)
    {
        $this->apcu_key = $cacheKey;
    }

    /**
     * @param int $ttl
     */
    public function setCacheTTL($ttl)
    {
        $this->apcu_ttl = $ttl;
    }
}
