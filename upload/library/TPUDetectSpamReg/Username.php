<?php

class TPUDetectSpamReg_Username
{
	static function getRegSpamScore(&$score, array $user, $verbose, $debug, $model)
	{
		$o=XenForo_Application::getOptions();

		if (trim($o->TPUDetectSpamRegUsername)!='')
		{
			$username=$user['username'];

			foreach (explode("\n", $o->TPUDetectSpamRegUsername) as $entry)
			{
				$entry=explode('|', trim($entry));
				if (count($entry)!=2)
					continue;

				list($points, $match)=$entry;

				$regex=$model->buildWildcardRegex($match);

				if (preg_match('/^'.$regex.'$/iU', $username))
				{
					$model->logScore('tpu_detectspamreg_username_fail', $points, array('username'=>$match));
					if (is_numeric($points))
						$score['points']+=$points;
					else
						$score[$points]=true;
				} else
					if ($debug)
						$model->logScore('tpu_detectspamreg_username_ok', 0, array('username'=>$match));
			}
		}
	}
}