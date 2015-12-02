<?php

class TPUDetectSpamReg_StopForumSpam
{
	static function getRegSpamScore(&$score, array $user, $verbose, $debug, $model)
	{
		$o=XenForo_Application::getOptions();

		if ($o->TPUDetectSpamRegSFSEnabled)
		{
			$apiResponse=$model->querySfs($user);

			if (is_array($apiResponse))
			{
				if (!empty($apiResponse['success']))
				{
					$flagsDetected=array();

					foreach (array('username', 'email', 'ip') as $flagName)
					{
						$flagsDetected[$flagName]=false;
						if (!empty($apiResponse[$flagName]))
						{
							$flag=$apiResponse[$flagName];

							if (!empty($flag['appears']))
							{
								if ($flag['lastseen']>=XenForo_Application::$time-7*86400)
									$flagsDetected[$flagName]=true;
							}

  						if ($debug)
  							if (!$flagsDetected[$flagName])
									$model->logScore('tpu_detectspamreg_sfs_ok', 0, array('flag'=>$flagName));
						}
					}

					if ($o->TPUDetectSpamRegSFSUsername>0)
					{
						if ($flagsDetected['username'])
						{
							$model->logScore('tpu_detectspamreg_sfs_fail', $o->TPUDetectSpamRegSFSUsername, array('flag'=>'username'));
							$score['points']+=$o->TPUDetectSpamRegSFSUsername;
						}
					}

					if ($o->TPUDetectSpamRegSFSEmail>0)
					{
						if ($flagsDetected['email'])
						{
							$model->logScore('tpu_detectspamreg_sfs_fail', $o->TPUDetectSpamRegSFSEmail, array('flag'=>'email'));
							$score['points']+=$o->TPUDetectSpamRegSFSEmail;
						}
					}

					if ($o->TPUDetectSpamRegSFSIp>0)
					{
						if ($flagsDetected['ip'])
						{
							$model->logScore('tpu_detectspamreg_sfs_fail', $o->TPUDetectSpamRegSFSIp, array('flag'=>'ip'));
							$score['points']+=$o->TPUDetectSpamRegSFSIp;
						}
					}
				}
			}
		}
	}
}