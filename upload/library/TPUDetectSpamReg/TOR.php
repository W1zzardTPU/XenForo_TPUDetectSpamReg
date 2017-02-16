<?php

class TPUDetectSpamReg_TOR
{
	static function reverseIP($ip)
	{
		$parts=explode('.', trim($ip));
		if (count($parts)!=4)
			return false;

		$parts=array_map('intval', $parts);
		$parts=array_reverse($parts);

		return implode('.', $parts);
	}

	static function getRegSpamScore(&$score, array $user, $verbose, $debug, $model)
	{
		$o=XenForo_Application::getOptions();

		if ($o->TPUDetectSpamRegTORScore!=0)
		{
			// Only IPv4 supported
			if (filter_var($user['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)==false)
				return;

			$srvIp=array();

			if ($o->TPUDetectSpamRegSrvIp!='')
			{
				$list=explode(',', $o->TPUDetectSpamRegSrvIp);
				foreach($list as $entry)
				{
					$entry=trim($entry);
					if ($entry!='')
					{
						$hosts=gethostbynamel($entry);
						if (is_array($hosts))
						{
							foreach($hosts as $ip)
							{
								// Only IPv4 supported
								if (filter_var($user['ip'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4))
								{
									$srvIp[]=$ip;
								}
							}
						}
					}
				}
			}

			if(!$srvIp)
			{
				if (isset($_SERVER['SERVER_ADDR']))
				$srvIp[]=$_SERVER['SERVER_ADDR'];
				elseif (isset($_SERVER['LOCAL_ADDR']))
				$srvIp[]=$_SERVER['LOCAL_ADDR'];
			}
			$srvIp=array_unique($srvIp);

			if (!$srvIp)
			{
				$model->logScore('Could not get server IP address for TOR detection module', 0);
				return;
			}

			$user_ip=self::reverseIP($user['ip']);
			$portsToCheck=array(80, 443);	// Check both HTTP and HTTPS
			foreach($srvIp as $ip)
			{
				foreach($portsToCheck as $port)
				{
					$q=sprintf('%s.%s.%s.ip-port.exitlist.torproject.org', $user_ip, $port, self::reverseIP($ip));
					if (gethostbyname($q)=='127.0.0.2')
					{
						$model->logScore('tpu_detectspamreg_tor_fail', $o->TPUDetectSpamRegTORScore);
						$score['points']+=$o->TPUDetectSpamRegTORScore;
						return;
					}
				}
			}
			if ($debug)
				$model->logScore('tpu_detectspamreg_tor_ok', 0);
		}
	}
}
