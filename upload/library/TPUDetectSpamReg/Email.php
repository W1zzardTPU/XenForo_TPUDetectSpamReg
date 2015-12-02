<?php

class TPUDetectSpamReg_Email
{
	static function getRegSpamScore(&$score, array $user, $verbose, $debug, $model)
	{
		$o=XenForo_Application::getOptions();

		if (trim($o->TPUDetectSpamRegEmail)!='')
		{
			$email=$user['email'];

			foreach (explode("\n", $o->TPUDetectSpamRegEmail) as $entry)
			{
				$entry=explode('|', trim($entry));
				if (count($entry)!=2)
					continue;

				list($points, $match)=$entry;

				$regex=$model->buildWildcardRegex($match);

				if (preg_match('/^'.$regex.'$/iU', $email))
				{
					$model->logScore('tpu_detectspamreg_email_fail', $points, array('email'=>$match));
					if (is_numeric($points))
						$score['points']+=$points;
					else
						$score[$points]=true;
				} else
					if ($debug)
						$model->logScore('tpu_detectspamreg_email_ok', 0, array('email'=>$match));
			}
		}
	}
}