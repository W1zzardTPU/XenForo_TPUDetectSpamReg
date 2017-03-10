<?php

class TPUDetectSpamReg_Hostname
{
	static function getRegSpamScore(&$score, array $user, $verbose, $debug, $model)
	{
		$o=XenForo_Application::getOptions();

		if (trim($o->TPUDetectSpamRegHostname)!='')
		{
			$hostname = empty($user['ip']) ? '' : gethostbyaddr($user['ip']);

			if ($verbose)
				$model->logScore('tpu_detectspamreg_hostname_detected', 0, array('hostname'=>$hostname));

			foreach (explode("\n", $o->TPUDetectSpamRegHostname) as $entry)
			{
				$entry=explode('|', trim($entry));
				if (count($entry)!=2)
					continue;

				list($points, $match)=$entry;

				$regex=$model->buildWildcardRegex($match);

				if (preg_match('/^'.$regex.'$/iU', $hostname))
				{
					$model->logScore('tpu_detectspamreg_hostname_fail', $points, array('hostname'=>$match));
					if (is_numeric($points))
						$score['points']+=$points;
					else
						$score[$points]=true;
				} elseif ($debug)
						$model->logScore('tpu_detectspamreg_hostname_ok', 0, array('hostname'=>$match));
			}
		}
	}
}
