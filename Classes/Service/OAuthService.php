<?php

declare(strict_types=1);

/*
 * This file is part of the TYPO3 CMS project.
 *
 * It is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, either version 2
 * of the License, or any later version.
 *
 * For the full copyright and license information, please read the
 * LICENSE.txt file that was distributed with this source code.
 *
 * The TYPO3 project - inspiring people to share!
 */

namespace Causal\Oidc\Service;

use Causal\Oidc\Factory\GenericOAuthProviderFactory;
use Causal\Oidc\Factory\OAuthProviderFactoryInterface;
use Causal\Oidc\OidcConfiguration;
use GuzzleHttp\RequestOptions;
use League\OAuth2\Client\Grant\AuthorizationCode;
use League\OAuth2\Client\Grant\Password;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessTokenInterface;
use RuntimeException;
use TYPO3\CMS\Core\Http\RequestFactory;
use TYPO3\CMS\Core\Utility\GeneralUtility;
use League\OAuth2\Client\Token\AccessToken;
use TYPO3\CMS\Frontend\Controller\TypoScriptFrontendController;

/**
 * Class OAuthService.
 */
class OAuthService
{
    protected OidcConfiguration $config;

    protected ?AbstractProvider $provider = null;

    public function __construct(OidcConfiguration $config)
    {
        $this->config = $config;
    }

    /**
     * Returns the authorization URL.
     *
     * @param array $options
     * @return string
     */
    public function getAuthorizationUrl(array $options = []): string
    {
        $languageOption = $this->config->authorizeLanguageParameter;
        if ($languageOption) {
            $language = $this->getTSFE() ? $this->getTSFE()->getLanguage()->getTwoLetterIsoCode() : 'en';
            $options[$languageOption] = $language;
        }

        return $this->getProvider()->getAuthorizationUrl($options);
    }

    /**
     * Returns the state generated for us.
     *
     * @return string
     * @see getAuthorizationUrl()
     */
    public function getState(): string
    {
        return $this->getProvider()->getState();
    }

    /**
     * Returns an AccessToken using either authorization code grant or resource owner password
     * credentials grant.
     *
     * @param string $codeOrUsername Either a code or the username (if password is provided)
     * @param string|null $password Optional parameter if authenticating with authorization code grant
     * @param string|null $codeVerifier Code verifier for PKCE
     * @return AccessToken
     * @throws IdentityProviderException
     */
    public function getAccessToken(string $codeOrUsername, ?string $password = null, ?string $codeVerifier = null): AccessToken
    {
        if ($password === null) {
            $options = [
                'code' => $codeOrUsername,
            ];
            if ($codeVerifier !== null) {
                $options['code_verifier'] = $codeVerifier;
            }
            $grant = new AuthorizationCode();
        } else {
            $options = [
                'username' => $codeOrUsername,
                'password' => $password,
                'scope' => $this->config->oidcClientScopes,
            ];
            // The GenericProvider has this as a public function (contrary to the interface),
            // so we use its scopes instead as there might be some modified provider.
            if (is_callable([$this->getProvider(), 'getDefaultScopes'])) {
                $options['scope'] = implode(',', $this->getProvider()->getDefaultScopes());
            }
            $grant = new Password();
        }
        return $this->getProvider()->getAccessToken($grant, $options);
    }

    /**
     * @throws IdentityProviderException
     */
    public function getAccessTokenForClient(): AccessTokenInterface
    {
        return $this->getProvider()->getAccessToken('client_credentials', [
            'scope' => implode(',', $this->getProvider()->getDefaultScopes()),
        ]);
    }

    /**
     * Returns an AccessToken using request path authentication.
     *
     * This non-standard behaviour is described on
     * https://docs.wso2.com/display/IS530/Try+Password+Grant
     *
     * @param string $username
     * @param string $password
     * @return AccessToken|null
     * @throws IdentityProviderException
     */
    public function getAccessTokenWithRequestPathAuthentication(string $username, string $password): ?AccessToken
    {
        $url = $this->config->endpointAuthorize . '?' . http_build_query([
                'response_type' => 'code',
                'client_id' => $this->config->oidcClientKey,
                'scope' => $this->config->oidcClientScopes,
                'redirect_uri' => $this->getRedirectUrl(),
            ]);

        $result = GeneralUtility::makeInstance(RequestFactory::class)->request(
            'GET',
            $url,
            [
                RequestOptions::AUTH => [$username, $password],
                RequestOptions::ALLOW_REDIRECTS => false
            ]
        );

        if ($result->getStatusCode() < 300 || $result->getStatusCode() >= 400) {
            throw new RuntimeException('Request failed', 1510049345);
        }

        if ($result->getHeader('Location')) {
            $targetUrl = $result->getHeader('Location')[0];
            $query = parse_url($targetUrl, PHP_URL_QUERY);
            parse_str($query, $queryParams);
            if (isset($queryParams['code'])) {
                return $this->getAccessToken($queryParams['code']);
            }
        }

        return null;
    }

    /**
     * Returns the resource owner.
     *
     * @param AccessToken $token
     * @return ResourceOwnerInterface
     */
    public function getResourceOwner(AccessToken $token): ResourceOwnerInterface
    {
        return $this->getProvider()->getResourceOwner($token);
    }

    /**
     * Revokes the access token.
     *
     * @param AccessToken $token
     * @return bool
     * @throws IdentityProviderException
     */
    public function revokeToken(AccessToken $token): bool
    {
        if (!$this->config->endpointRevoke) {
            return false;
        }

        $provider = $this->getProvider();
        $request = $provider->getRequest(
            AbstractProvider::METHOD_POST,
            $this->config->endpointRevoke,
            [
                'headers' => [
                    'Authorization' => 'Basic ' . base64_encode($this->config->oidcClientKey . ':' . $this->config->oidcClientSecret),
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
                'body' => 'token=' . $token->getToken(),
            ]
        );

        $response = $provider->getParsedResponse($request);
        // TODO error handling?

        return true;
    }

    protected function getProvider(): AbstractProvider
    {
        if ($this->provider === null) {
            $factoryClass = $this->config->oauthProviderFactory ?: GenericOAuthProviderFactory::class;
            if (!is_a($factoryClass, OAuthProviderFactoryInterface::class, true)) {
                throw new RuntimeException('OAuth provider factory class must implement the OAuthProviderFactoryInterface', 1652689564769);
            }

            $settings = $this->config;
            $settings->oidcRedirectUri = $this->getRedirectUrl();

            /** @var OAuthProviderFactoryInterface $factory */
            $factory = GeneralUtility::makeInstance($factoryClass);
            $this->provider = $factory->create($settings);
        }

        return $this->provider;
    }

    public function getFreshAccessToken(): ?AccessToken
    {
        $serializedToken = ''; // @todo current access_token
        $options = json_decode($serializedToken, true);
        if (empty($serializedToken) || empty($options)) {
            // Invalid token
            return null;
        }
        $accessToken = new AccessToken($options);

        if ($accessToken->hasExpired()) {
            try {
                $newAccessToken = $this->getProvider()->getAccessToken('refresh_token', [
                    'refresh_token' => $accessToken->getRefreshToken(),
                ]);

                // TODO
            } catch (IdentityProviderException $e) {
                // TODO: log problem
                return null;
            }
        }

        return $accessToken;
    }

    protected function getRedirectUrl(): string
    {
        return $this->config->oidcRedirectUri ?: GeneralUtility::getIndpEnv('TYPO3_SITE_URL');
    }

    protected function getTSFE(): ? TypoScriptFrontendController
    {
        return $GLOBALS['TSFE'] ?? null;
    }
}
