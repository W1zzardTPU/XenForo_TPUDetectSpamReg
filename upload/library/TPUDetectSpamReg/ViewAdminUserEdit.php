<?php

class TPUDetectSpamReg_ViewAdminUserEdit extends XFCP_TPUDetectSpamReg_ViewAdminUserEdit
{
	public function renderHtml()
	{
		if ($this->_params['user']['user_id']>0)
		{
			$rows = XenForo_Application::getDb()->fetchAll('
				SELECT log.*,
					user.*
				FROM xf_spam_trigger_log AS log
				LEFT JOIN xf_user AS user ON (log.user_id = user.user_id)
				WHERE log.content_type = ?
					AND log.user_id = ?
			', array('user', $this->_params['user']['user_id']));

			if ($rows)
			{
                $model = XenForo_Model::create('XenForo_Model_SpamPrevention');
                $output = [];
			    foreach($rows as $row)
                {
                    $row = $model->prepareSpamTriggerLog($row);

                    $item = [];
                    foreach ($row['detailsPrintable'] as $line)
                    {
                        $item[] = $line->render();
                    }
                    $output[] =  join('<br />', $item);
                }

                $this->_params['tpudetectspamreg_log'] = join('<br />', $output);
			}
		}

		parent::renderHtml();
	}
}
