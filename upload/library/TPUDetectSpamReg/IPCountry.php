<?php

class TPUDetectSpamReg_IPCountry
{
	static function getIPCountry($ip)
	{
		if (function_exists('geoip_db_avail') && geoip_db_avail(GEOIP_COUNTRY_EDITION))
		{
			try 
			{
				try
				{
					return geoip_country_code_by_name($ip);
				} catch(Exception $e) {}
			} catch(ErrorException $e) {}
		}

		try
		{
			$country=json_decode(file_get_contents('http://ip-api.com/json/'.$ip));
			if (isset($country) && isset($country->countryCode) && $country->countryCode!='')
				return $country->countryCode;
		} catch(Exception $e) {}

		try
		{
			$country=json_decode(file_get_contents('https://freegeoip.net/json/'.$ip));
			if (isset($country) && isset($country->country_code) && $country->country_code!='')
				return $country->country_code;
		} catch(Exception $e) {}

		return 'XX';
	}

	static function getRegSpamScore(&$score, array $user, $verbose, $debug, $model)
	{
		$o=XenForo_Application::getOptions();

		if (trim($o->TPUDetectSpamRegIPCountry)!='')
		{
			$ipCountry=self::getIPCountry($user['ip']);

			if ($verbose)
				$model->logScore('tpu_detectspamreg_country_detected', 0, array('country'=>$ipCountry));

			foreach (explode("\n", $o->TPUDetectSpamRegIPCountry) as $entry)
			{
				$entry=explode('|', trim($entry));

				if (count($entry)!=2)
					continue;

				list($points, $country)=$entry;

				if (strcasecmp($country, $ipCountry)==0)
				{
					$model->logScore('tpu_detectspamreg_country_fail', $points, array('country'=>$country));
					if (is_numeric($points))
						$score['points']+=$points;
					else
						$score[$points]=true;
				}
				else
				{
					if ($debug)
						$model->logScore('tpu_detectspamreg_country_ok', 0, array('country'=>$country));
				}
			}
		}
	}
}