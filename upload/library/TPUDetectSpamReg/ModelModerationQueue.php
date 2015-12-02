<?php

class TPUDetectSpamReg_ModelModerationQueue extends XFCP_TPUDetectSpamReg_ModelModerationQueue
{
	public function getVisibleModerationQueueEntriesForUser(array $queue, array $viewingUser = null)
	{
		$result=parent::getVisibleModerationQueueEntriesForUser($queue, $viewingUser);

		foreach ($result as &$entry)
		{
			if (($entry['content_type']=='post') || ($entry['content_type']=='thread'))
			{
				if ($entry['content']['user']['user_id']>0)
				{
					$row=XenForo_Application::getDb()->fetchRow("
						SELECT log.*,
							user.*
						FROM xf_spam_trigger_log AS log
						LEFT JOIN xf_user AS user ON (log.user_id = user.user_id)
						WHERE log.content_type = ?
							AND log.user_id = ?
					", array('user', $entry['content']['user']['user_id']));
				
					if ($row)
					{
						$row=XenForo_Model::create('XenForo_Model_SpamPrevention')->prepareSpamTriggerLog($row);
						
						$output=array();
						foreach ($row['detailsPrintable'] as $line)
							$output[]=$line->render();
						$output=join('<br />', $output);
						
						$entry['content']['tpudetectspamreg_log']=$output;
					}
				}
			}
		}
		
		return $result;
	}
}