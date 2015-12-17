<?php

class TPUDetectSpamReg_AS
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

	static function reverseIPv6($ip)
	{
		$addr = inet_pton($ip);
		$unpack = unpack('H*hex', $addr);
		$hex = $unpack['hex'];
		return implode('.', array_reverse(str_split($hex)));
	}

	static function isIPv6($ip) 
	{
		return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
	}
	
	static function getASNameAndNumber($ip, &$asNumber, &$asName)
	{
		try 
		{
			if (self::isIPv6($ip))
				$dns=dns_get_record(self::reverseIPv6($ip).'.origin6.asn.cymru.com', DNS_TXT);
			else
				$dns=dns_get_record(self::reverseIP($ip).'.origin.asn.cymru.com', DNS_TXT);
		} catch(Exception $e) {}
			
		if (isset($dns[0]['txt']))
		{
			$items=explode('|', $dns[0]['txt'], 2);
			$items=array_shift($items);
			$asNumber=intval($items);
			if ($asNumber>0)
			{
				$dns=dns_get_record('AS'.$asNumber.'.asn.cymru.com', DNS_TXT);
				if (isset($dns[0]['txt']))
				{
					$tokens=explode('|', $dns[0]['txt']);
					$asName=trim($tokens[4]);

					return TRUE;
				}
			}
		}

		return FALSE;

		// Old slow code
		try {
			$networkinfo=json_decode(file_get_contents('https://stat.ripe.net/data/network-info/data.json?resource='.$ip));
			$asNumber=$networkinfo->data->asns[0];
			$asInfo=json_decode(file_get_contents('https://stat.ripe.net/data/as-overview/data.json?resource=AS'.$asNumber));
			$asName=$asInfo->data->holder;

			return TRUE;
		} catch (Exception $e) {};

		return FALSE;
	}

	static function getRegSpamScore(&$score, array $user, $verbose, $debug, $model)
	{
		$o=XenForo_Application::getOptions();

		if (trim($o->TPUDetectSpamRegAS)!='')
		{
			if (self::getASNameAndNumber($user['ip'], $asNumber, $asName))
			{
				if ($verbose)
					$model->logScore('tpu_detectspamreg_as_detected', 0, array('number'=>$asNumber, 'name'=>$asName));

				foreach (explode("\n", $o->TPUDetectSpamRegAS) as $entry)
				{
					$entry=explode('|', trim($entry));
					if (count($entry)!=2)
						continue;

					list($points, $match)=$entry;

					if ((is_numeric($match)) && ($match>0))
					{
						if ((int)$match==(int)$asNumber)
						{
							$model->logScore('tpu_detectspamreg_as_fail', $points, array('number'=>$asNumber, 'name'=>$asName));
												if (is_numeric($points))
														$score['points']+=$points;
												else
														$score[$points]=true;
						}
					} else
					{
						$asName=strtok($asName, ' ');
						$regex=$model->buildWildcardRegex($match);

						if (preg_match('/^'.$regex.'$/iU', $asName))
						{
							$model->logScore('tpu_detectspamreg_as_fail', $points, array('number'=>$asNumber, 'name'=>$asName));
							if (is_numeric($points))
									$score['points']+=$points;
							else
									$score[$points]=true;
						} else
							if ($debug)
								$model->logScore('tpu_detectspamreg_as_ok', 0, array('number'=>$asNumber, 'name'=>$match));
					}
				}
			}
		}
	}
}