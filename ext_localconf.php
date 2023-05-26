<?php
defined('TYPO3') or die();

// Configuration of authentication service
$settings = \TYPO3\CMS\Core\Utility\GeneralUtility::makeInstance(\TYPO3\CMS\Core\Configuration\ExtensionConfiguration::class)->get('oidc') ?? [];

// Service configuration
$subTypesArr = [];
$subTypes = '';
if ($settings['enableFrontendAuthentication'] ?? '') {
    $subTypesArr[] = 'getUserFE';
    $subTypesArr[] = 'authUserFE';
    $subTypesArr[] = 'getGroupsFE';
}
if (is_array($subTypesArr)) {
    $subTypesArr = array_unique($subTypesArr);
    $subTypes = implode(',', $subTypesArr);
}

$authenticationClassName = \Causal\Oidc\Service\AuthenticationService::class;
\TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addService(
    'oidc',
    'auth' /* sv type */,
    $authenticationClassName /* sv key */,
    [
        'title' => 'Authentication service',
        'description' => 'Authentication service for OpenID Connect.',
        'subtype' => $subTypes,
        'available' => true,
        'priority' => (int)($settings['authenticationServicePriority'] ?? 82),
        'quality' => (int)($settings['authenticationServiceQuality'] ?? 80),
        'os' => '',
        'exec' => '',
        'className' => $authenticationClassName,
    ]
);

\TYPO3\CMS\Extbase\Utility\ExtensionUtility::configurePlugin(
    'oidc',
    'Pi1',
    [
        \Causal\Oidc\Controller\AuthenticationController::class => 'connect',
    ],
    // non-cacheable actions
    [
        \Causal\Oidc\Controller\AuthenticationController::class => 'connect'
    ]
);

    if (\TYPO3\CMS\Core\Utility\ExtensionManagementUtility::isLoaded('felogin')) {
        $GLOBALS['TYPO3_CONF_VARS']['EXTCONF']['felogin']['postProcContent'][$_EXTKEY] = \Causal\Oidc\Hooks\FeloginHook::class . '->postProcContent';
    }

    // Add typoscript for custom login plugin
    \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addPItoST43('oidc', null, '_login');

// Require 3rd-party libraries, in case TYPO3 does not run in composer mode
$pharFileName = \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::extPath('oidc') . 'Libraries/league-oauth2-client.phar';
if (is_file($pharFileName)) {
    @include 'phar://' . $pharFileName . '/vendor/autoload.php';
}
