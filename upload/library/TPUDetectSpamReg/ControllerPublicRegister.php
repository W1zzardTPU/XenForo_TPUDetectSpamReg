<?php

class TPUDetectSpamReg_ControllerPublicRegister extends XFCP_TPUDetectSpamReg_ControllerPublicRegister
{
	protected function _completeRegistration(array $user, array $extraParams = array())
	{
		$result=parent::_completeRegistration($user, $extraParams);
		
		if (class_exists('TPUDetectSpamReg_ModelSpamPrevention', false))
		{
			if (TPUDetectSpamReg_ModelSpamPrevention::$moderateAllPosts)
			{
				$permissions=array('general'=>array('TPUSpamRegModAllPosts'=>'allow'));
				$this->getModelFromCache('XenForo_Model_Permission')->updateGlobalPermissionsForUserCollection($permissions, 0, $user['user_id']);
			}
		}

		return $result;
	}
}