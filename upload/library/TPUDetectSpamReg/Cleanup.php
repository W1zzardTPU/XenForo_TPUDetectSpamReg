<?php

class TPUDetectSpamReg_Cleanup
{
	public static function cleanup()
	{
		$o=XenForo_Application::getOptions();

		// Remove permanently banned users from user-permissions to improve performance
		$userIds=XenForo_Application::getDb()->fetchAll('SELECT xf_permission_entry.user_id FROM xf_permission_entry LEFT JOIN xf_user ON xf_permission_entry.user_id=xf_user.user_id LEFT JOIN xf_user_ban ON xf_permission_entry.user_id=xf_user_ban.user_id WHERE permission_id="TPUSpamRegModAllPosts" AND xf_permission_entry.user_id!=0 AND end_date=0');
		foreach($userIds as $row)
		{
			$permissions=array('general'=>array('TPUSpamRegModAllPosts'=>'unset'));
			XenForo_Model::create('XenForo_Model_Permission')->updateGlobalPermissionsForUserCollection($permissions, 0, $row['user_id']);
		}

		// Permanently delete users who have made no posts and haven't logged on for x days
		if ($o->TPUDetectSpamRegScoreModPosts['purgedays']>0)
		{
			$userIds=XenForo_Application::getDb()->fetchAll('SELECT xf_permission_entry.user_id FROM xf_permission_entry LEFT JOIN xf_user ON xf_permission_entry.user_id=xf_user.user_id WHERE permission_id="TPUSpamRegModAllPosts" AND xf_permission_entry.user_id!=0 AND message_count=0 AND last_activity<UNIX_TIMESTAMP(DATE_SUB(NOW(), INTERVAL ? DAY))', array($o->TPUDetectSpamRegScoreModPosts['purgedays']));

			foreach($userIds as $row)
			{
				// Let's make sure the user has no deleted posts
				$hasPosts=XenForo_Application::getDb()->fetchOne('SELECT user_id FROM xf_post WHERE user_id=?', $row['user_id']);
				if ($hasPosts!==false)
					continue;

				$writer = XenForo_DataWriter::create('XenForo_DataWriter_User', XenForo_DataWriter::ERROR_EXCEPTION);
				$writer->setExistingData($row);
				$writer->delete();
			}
		}
	}
}
