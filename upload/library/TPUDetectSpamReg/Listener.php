<?php

class TPUDetectSpamReg_Listener
{
	public static function listenModel($class, &$extend)
	{
        $extend[] = 'TPUDetectSpamReg_ModelSpamPrevention';
	}

	public static function listenModelModQ($class, &$extend)
    {
        if (XenForo_Application::getOptions()->TPUDetectSpamRegShowInModQ)
        {
            $extend[] = 'TPUDetectSpamReg_ModelModerationQueue';
        }
    }

    public static function listenModelUser($class, &$extend)
    {
        $extend[] = 'TPUDetectSpamReg_ModelUser';
    }

	public static function listenController($class, &$extend)
	{
		$extend[] = 'TPUDetectSpamReg_ControllerPublicRegister';
	}

	public static function listenViewAdmin($class, &$extend)
	{
		$extend[] = 'TPUDetectSpamReg_ViewAdminUserEdit';
	}
}
