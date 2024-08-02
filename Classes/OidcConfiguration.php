<?php

declare(strict_types=1);

namespace Causal\Oidc;

use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Utility\GeneralUtility;

final class OidcConfiguration
{
    public int $usersStoragePid = 0;
    public string $usersDefaultGroup = '';
    public bool $reEnableFrontendUsers = false;
    public bool $undeleteFrontendUsers = false;
    public bool $frontendUserMustExistLocally = false;
    public bool $disableCSRFProtection = false;
    public bool $enableCodeVerifier = false;
    public string $authenticationUrlRoute = 'oidc/authentication';
    public string $authorizeLanguageParameter = 'language';
    public bool $useRequestPathAuthentication = false;
    public string $oauthProviderFactory = '';
    public string $oidcClientKey = '';
    public string $oidcClientSecret = '';
    public string $oidcClientScopes = 'openid';
    public string $oidcRedirectUri = '';
    public string $endpointAuthorize = 'https://ids02.sac-cas.ch/oauth2/authorize';
    public string $endpointToken = 'https://ids02.sac-cas.ch/oauth2/token';
    public string $endpointUserInfo = 'https://ids02.sac-cas.ch/oauth2/userinfo';
    public string $endpointRevoke = 'https://ids02.sac-cas.ch/oauth2/revoke';
    public string $endpointLogout = 'https://ids02.sac-cas.ch/oauth2/logout';
    public bool $revokeAccessTokenAfterLogin = false;

    public function __construct()
    {
        $extConfig = GeneralUtility::makeInstance(ExtensionConfiguration::class)->get('oidc') ?? [];

        $config = new self();
        $config->reEnableFrontendUsers = (bool)$extConfig['reEnableFrontendUsers'];
        $config->undeleteFrontendUsers = (bool)$extConfig['undeleteFrontendUsers'];
        $config->frontendUserMustExistLocally = (bool)$extConfig['frontendUserMustExistLocally'];
        $config->disableCSRFProtection = (bool)$extConfig['oidcDisableCSRFProtection'];
        $config->enableCodeVerifier = (bool)$extConfig['enableCodeVerifier'];
        $config->authenticationUrlRoute = $extConfig['authenticationUrlRoute'];
        $config->authorizeLanguageParameter = $extConfig['oidcAuthorizeLanguageParameter'];
        $config->useRequestPathAuthentication = (bool)$extConfig['oidcUseRequestPathAuthentication'];
        $config->oauthProviderFactory = $extConfig['oauthProviderFactory'];
        $config->oidcClientKey = $extConfig['oidcClientKey'];
        $config->oidcClientSecret = $extConfig['oidcClientSecret'];
        $config->oidcClientScopes = $extConfig['oidcClientScopes'];
        $config->endpointAuthorize = $extConfig['oidcEndpointAuthorize'];
        $config->endpointToken = $extConfig['oidcEndpointToken'];
        $config->endpointUserInfo = $extConfig['oidcEndpointUserInfo'];
        $config->endpointRevoke = $extConfig['oidcEndpointRevoke'];
        $config->endpointLogout = $extConfig['oidcEndpointLogout'];
        $config->usersStoragePid = (int)$extConfig['usersStoragePid'];
        $config->usersDefaultGroup = $extConfig['usersDefaultGroup'];
        $config->oidcRedirectUri = $extConfig['oidcRedirectUri'];
        $config->revokeAccessTokenAfterLogin = (bool)$extConfig['oidcRevokeAccessTokenAfterLogin'];

        return $config;
    }
}
