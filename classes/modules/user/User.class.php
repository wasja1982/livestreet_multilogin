<?php
/**
 * MultiLogin - авторизация без сброса cookie
 *
 * Версия:	1.0.0
 * Автор:	Александр Вереник
 * Профиль:	http://livestreet.ru/profile/Wasja/
 * GitHub:	https://github.com/wasja1982/livestreet_multilogin
 *
 **/

class PluginMultilogin_ModuleUser extends PluginMultilogin_Inherit_ModuleUser {
    /**
     * Авторизовывает юзера
     *
     * @param ModuleUser_EntityUser $oUser	Объект пользователя
     * @param bool $bRemember	Запоминать пользователя или нет
     * @param string $sKey	Ключ авторизации для куков
     * @return bool
     */
    public function Authorization(ModuleUser_EntityUser $oUser,$bRemember=true,$sKey=null) {
        if ($oUser->isAdministrator()) {
            return parent::Authorization($oUser, $bRemember, $sKey);
        }
        $bSkip = $bRemember;
        if (!$sKey) {
            $oSession = $this->GetSessionByUserId($oUser->getId());
            if ($oSession) {
                $sKey = $oSession->getKey();
            } elseif (isset($_COOKIE['key']) && is_string($_COOKIE['key'])) {
                $sKey = $_COOKIE['key'];
            }
        }
        if (isset($_COOKIE['key']) && is_string($_COOKIE['key'])) {
            $bSkip = false;
        }
        $bResult = parent::Authorization($oUser, false, $sKey);
        if ($bResult && $bSkip) {
            setcookie('key',$sKey,time()+Config::Get('sys.cookie.time'),Config::Get('sys.cookie.path'),Config::Get('sys.cookie.host'),false,true);
        }
        return $bResult;
    }
    /**
     * Разлогинивание
     *
     */
    public function Logout() {
        if ($this->oSession && $this->oUserCurrent && 
            isset($_COOKIE['key']) && is_string($_COOKIE['key']) && $_COOKIE['key'] === $this->oSession->getKey()) {
            $sKey = md5(func_generator() . time() . $this->oUserCurrent->getLogin());
            $this->oSession->setKey($sKey);
            $this->oMapper->CreateSession($this->oSession);
            $data = array(
                'time' => time(),
                'session' => $this->oSession
            );
            $this->Cache_Set($data, "user_session_{$this->oSession->getUserId()}", array(), 60*60*24*4);
        }
        parent::Logout();
    }
}
?>