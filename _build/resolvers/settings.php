<?php
/** @var xPDOTransport $transport */
/** @var array $options */
/** @var modX $modx */
if ($transport->xpdo) {
    $modx =& $transport->xpdo;
    /** @var array $options */
    switch ($options[xPDOTransport::PACKAGE_ACTION]) {
        case xPDOTransport::ACTION_INSTALL:
        case xPDOTransport::ACTION_UPGRADE:
            $modx->addExtensionPackage('jwtsession', '[[++core_path]]components/jwtsession/model/', [
                'serviceName' => 'jwtSession',
                'serviceClass' => 'jwtSession',
            ]);
            /** @var modSystemSetting $setting */
            if ($setting = $modx->getObject('modSystemSetting', ['key' => 'session_handler_class'])) {
                $setting->set('value', 'jwtSession');
                $setting->save();
            }
            break;

        case xPDOTransport::ACTION_UNINSTALL:
            $modx->removeExtensionPackage('jwtsession');
            if ($setting = $modx->getObject('modSystemSetting', ['key' => 'session_handler_class'])) {
                $setting->set('value', 'modSessionHandler');
                $setting->save();
            }
            break;
    }
}

return true;