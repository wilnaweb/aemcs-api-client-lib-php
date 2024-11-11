<?php
namespace AEMCsApiClientLibPHP;

// Include required dependencies
require_once 'vendor/autoload.php'; // Composer autoload for dependencies like Guzzle, JWT, etc.

use GuzzleHttp\Client;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GuzzleHttp\Exception\RequestException;
use \Exception;

class IMSJWTTokenExchange {
    private $host;
    private $client;

    public function __construct($host, $proxy = null) {
        if ($host === null) {
            throw new Exception("Client lib must have a target host defined, imsHost or jilHost");
        }

        $this->host = $host;

        $config = [
            'base_uri' => 'https://' . $this->host,
            'timeout'  => 10.0,
        ];

        if ($proxy) {
            $config['proxy'] = 'http://' . $proxy['host'] . ':' . $proxy['port'];
        }

        $this->client = new Client($config);
    }

    public function checkRequired($options, $key) {
        if (!isset($options[$key])) {
            throw new Exception("$key is a required option.");
        }
    }

    public function exchangeJwt($options) {
        // Check for required options
        $this->checkRequired($options, "issuer");
        $this->checkRequired($options, "subject");
        $this->checkRequired($options, "expiration_time_seconds");
        $this->checkRequired($options, "metascope");
        $this->checkRequired($options, "client_id");
        $this->checkRequired($options, "client_secret");
        $this->checkRequired($options, "privateKey");

        // Prepare JWT payload
        $jwt_payload = [
            'iss' => $options['issuer'],
            'sub' => $options['subject'],
            'exp' => $options['expiration_time_seconds'],
            'aud' => 'https://' . $this->host . '/c/' . $options['client_id'],
        ];

        foreach ($options['metascope'] as $scope) {
            $jwt_payload['https://' . $this->host . '/s/' . $scope] = true;
        }

        // Sign the JWT with RSA256
        $jwt_token = JWT::encode($jwt_payload, $options['privateKey'], 'RS256');
        $decode = '';
        if (isset($options['publicKey'])) {
            $headers = (object) array();
            $decode = json_encode(JWT::decode($jwt_token, new Key($options['publicKey'],'RS256'), $headers));
        }
        
        // Prepare request body
        $body = [
            'client_id' => $options['client_id'],
            'client_secret' => $options['client_secret'],
            'jwt_token' => $jwt_token,
        ];

        try {
            // Make the POST request to exchange JWT
            $response = $this->client->post('/ims/exchange/jwt', [
                'form_params' => $body,
                'headers' => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
            ]);

            $statusCode = $response->getStatusCode();
            if ($statusCode === 200) {
                return json_decode($response->getBody(), true);
            } else {
                throw new Exception("Failed to exchange JWT.");
            }
        } catch (RequestException $e) {
            //echo 'Request failed: ' . $e->getMessage();
            throw $e;
        }
    }
}

// Function to check required fields in configuration
function assertPresent($config, $path, &$missing) {
    $pathElements = explode('.', $path);
    $c = $config;
    foreach ($pathElements as $p) {
        if (!isset($c[$p])) {
            $missing[] = $path;
            return;
        }
        $c = $c[$p];
    }
}

function exchangeToken($integrationConfig) {
    $jwtExchange = null;
    if (isset($integrationConfig['proxy'])) {
        $jwtExchange = new IMSJWTTokenExchange($integrationConfig['integration']['imsEndpoint'], $integrationConfig['proxy']);
    } else {
        $jwtExchange = new IMSJWTTokenExchange($integrationConfig['integration']['imsEndpoint']);
    }

    $missing = [];
    assertPresent($integrationConfig, 'integration.org', $missing);
    assertPresent($integrationConfig, 'integration.id', $missing);
    assertPresent($integrationConfig, 'integration.technicalAccount.clientId', $missing);
    assertPresent($integrationConfig, 'integration.technicalAccount.clientSecret', $missing);
    assertPresent($integrationConfig, 'integration.metascopes', $missing);
    assertPresent($integrationConfig, 'integration.privateKey', $missing);
    assertPresent($integrationConfig, 'integration.publicKey', $missing);

    if (count($missing) > 0) {
        throw new Exception('The following configuration elements are missing: ' . implode(',', $missing));
    }

    return $jwtExchange->exchangeJwt([
        'issuer' => $integrationConfig['integration']['org'],
        'subject' => $integrationConfig['integration']['id'],
        'expiration_time_seconds' => floor(time() + 3600 * 8),
        'metascope' => explode(',', $integrationConfig['integration']['metascopes']),
        'client_id' => $integrationConfig['integration']['technicalAccount']['clientId'],
        'client_secret' => $integrationConfig['integration']['technicalAccount']['clientSecret'],
        'privateKey' => $integrationConfig['integration']['privateKey'],
        'publicKey' => $integrationConfig['integration']['publicKey'],
    ]);
}