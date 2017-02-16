<?php

class TPUDetectSpamReg_HoneyPot
{
	static function getRegSpamScore(&$score, array $user, $verbose, $debug, $model)
	{
		$o=XenForo_Application::getOptions();

		if ($o->TPUDetectSpamRegHoneyPotEnabled)
		{
			// Only IPv4 supported
			if (filter_var($user['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)==false)
				return;

			$dnsBl=new XenForo_DnsBl($o->TPUDetectSpamRegHoneyPotAPIKey.'.%s.dnsbl.httpbl.org');
			$res=$dnsBl->checkIp($user['ip']);
			if (is_array($res))
			{
				if ($res[0]=='127')
				{
					$lastSeen=intval($res[1]);
					$threatLevel=intval($res[2]);

					if ($lastSeen<$o->TPUDetectSpamRegHoneyPotCutoff)
					{
						$scoreToGive=0;

						if (($threatLevel>=10) && ($threatLevel<20))
							$scoreToGive=$o->TPUDetectSpamRegHoneyPotScore10;
						elseif (($threatLevel>=20) && ($threatLevel<40))
							$scoreToGive=$o->TPUDetectSpamRegHoneyPotScore20;
						elseif (($threatLevel>=40) && ($threatLevel<60))
							$scoreToGive=$o->TPUDetectSpamRegHoneyPotScore40;
						elseif (($threatLevel>=60) && ($threatLevel<80))
							$scoreToGive=$o->TPUDetectSpamRegHoneyPotScore60;
						elseif (($threatLevel>=80) && ($threatLevel<100))
							$scoreToGive=$o->TPUDetectSpamRegHoneyPotScore80;

						if ($scoreToGive!=0)
						{
							$model->logScore('tpu_detectspamreg_honeypot_fail', $scoreToGive, array('lastseen'=>$lastSeen, 'threatlevel'=>$threatLevel));
							$score['points']+=$scoreToGive;
						} else
							$model->logScore('tpu_detectspamreg_honeypot_pass', 0, array('lastseen'=>$lastSeen, 'threatlevel'=>$threatLevel));
					} else
						$model->logScore('tpu_detectspamreg_honeypot_ok', 0);
				}
			}
		}
	}
}
