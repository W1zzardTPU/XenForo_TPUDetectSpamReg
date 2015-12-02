<?php

class TPUDetectSpamReg_Listener
{
	public static function listenModel($class, &$extend)
	{
		if ($class=='XenForo_Model_SpamPrevention')
		{
			$extend[] = 'TPUDetectSpamReg_ModelSpamPrevention';
		}
	}
	
	public static function listenModelModQ($class, &$extend)
	{
		if ($class=='XenForo_Model_ModerationQueue')
		{
			if (XenForo_Application::getOptions()->TPUDetectSpamRegShowInModQ)
				$extend[] = 'TPUDetectSpamReg_ModelModerationQueue';
		}
	}	

	public static function listenController($class, &$extend)
	{
		if ($class=='XenForo_ControllerPublic_Register')
		{
			$extend[] = 'TPUDetectSpamReg_ControllerPublicRegister';
		}
	}
	
	public static function listenViewAdmin($class, &$extend)
	{
		if ($class=='XenForo_ViewAdmin_User_Edit')
		{
			$extend[] = 'TPUDetectSpamReg_ViewAdminUserEdit';
		}
	}
}
