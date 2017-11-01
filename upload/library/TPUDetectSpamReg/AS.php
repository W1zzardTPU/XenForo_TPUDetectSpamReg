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

	static function getASNameAndNumber_cymru($ip, &$asNumber, &$asName)
	{
		if (empty($ip))
			return false;

		$dns = null;
		try
		{
			if (self::isIPv6($ip))
				$dns=dns_get_record(self::reverseIPv6($ip).'.origin6.asn.cymru.com', DNS_TXT);
			else
				$dns=dns_get_record(self::reverseIP($ip).'.origin.asn.cymru.com', DNS_TXT);
		} catch(Exception $e) {}

		if (!empty($dns[0]['txt']))
		{
			$items=explode('|', $dns[0]['txt'], 2);
			$items=array_shift($items);
			$asNumber=intval($items);
			if ($asNumber>0)
			{
				$dns=dns_get_record('AS'.$asNumber.'.asn.cymru.com', DNS_TXT);
				if (!empty($dns[0]['txt']))
				{
					$tokens=explode('|', $dns[0]['txt']);
					$asName=trim($tokens[4]);

					return true;
				}
			}
		}

		return false;
	}

	static function getASNameAndNumber_ripe($ip, &$asNumber, &$asName)
	{
		if (empty($ip)) return false;
		// Old slow code
		try {
			$networkinfo=json_decode(file_get_contents('https://stat.ripe.net/data/network-info/data.json?resource='.$ip));
			$asNumber=$networkinfo->data->asns[0];
			$asInfo=json_decode(file_get_contents('https://stat.ripe.net/data/as-overview/data.json?resource=AS'.$asNumber));
			$asName=$asInfo->data->holder;

			return true;
		} catch (Exception $e) {};

		return false;
	}

	static function getASNameAndNumber_moocherio($ip, &$asNumber, &$asName)
	{
		if (empty($ip)) return false;
		$curl = curl_init();

		curl_setopt_array($curl, array(
			CURLOPT_URL => 'http://api.moocher.io/as/ip/'.$ip,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_ENCODING => '',
			CURLOPT_MAXREDIRS => 1,
			CURLOPT_TIMEOUT => 1,
			CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
			CURLOPT_CUSTOMREQUEST => 'GET',
			CURLOPT_HTTPHEADER => array(
			'content-type: application/json'
			),
		));

		$response = curl_exec($curl);
		$err = curl_error($curl);
		$http_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		curl_close($curl);

		if ($http_code == 200)
		{
			$json = @json_decode($response, true);
			if (isset($json['as']['name']) || isset($json['as']['asn']))
			{
				$asName = @$json['as']['name'];
				$asNumber = @$json['as']['asn'];
				//$country = @$json['as']['country'];
				return true;
			}
		}
		return false;
	}

	static function getRegSpamScore(&$score, array $user, $verbose, $debug, $model)
	{
		$o=XenForo_Application::getOptions();

		if (trim($o->TPUDetectSpamRegAS)!='')
		{
			if (($o->tpu_asn_cymru && self::getASNameAndNumber_cymru($user['ip'], $asNumber, $asName)) ||
				($o->tpu_asn_moocherio && self::getASNameAndNumber_moocherio($user['ip'], $asNumber, $asName)) ||
				($o->tpu_asn_ripe && self::getASNameAndNumber_ripe($user['ip'], $asNumber, $asName)))
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
						} elseif ($debug)
								$model->logScore('tpu_detectspamreg_as_ok', 0, array('number'=>$asNumber, 'name'=>$match));
					}
				}
			}
		}
	}
}
