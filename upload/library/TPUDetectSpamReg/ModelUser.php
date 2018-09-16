<?php

class TPUDetectSpamReg_ModelUser extends XFCP_TPUDetectSpamReg_ModelUser
{
    public function __construct()
    {
        parent::__construct();
        XenForo_Model_User::$userContentChanges['xf_spam_trigger_log'] = array(array('user_id', false, false));
    }
}

if (false)
{
    class XFCP_TPUDetectSpamReg_ModelUser extends XenForo_Model_User {}
}
