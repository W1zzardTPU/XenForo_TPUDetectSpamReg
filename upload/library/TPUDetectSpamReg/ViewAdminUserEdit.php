<?php

class TPUDetectSpamReg_ViewAdminUserEdit extends XFCP_TPUDetectSpamReg_ViewAdminUserEdit
{
	public function renderHtml()
	{
		if ($this->_params['user']['user_id']>0)
		{
			$row=XenForo_Application::getDb()->fetchRow("
				SELECT log.*,
					user.*
				FROM xf_spam_trigger_log AS log
				LEFT JOIN xf_user AS user ON (log.user_id = user.user_id)
				WHERE log.content_type = ?
					AND log.user_id = ?
			", array('user', $this->_params['user']['user_id']));
			
			if ($row)
			{
				$row=XenForo_Model::create('XenForo_Model_SpamPrevention')->prepareSpamTriggerLog($row);
				
				$output=array();
				foreach ($row['detailsPrintable'] as $line)
					$output[]=$line->render();
				$output=join('<br />', $output);
				
				$this->_params['tpudetectspamreg_log']=$output;
			}
		}

		parent::renderHtml();
	}
}