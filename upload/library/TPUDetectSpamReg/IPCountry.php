<?php

class TPUDetectSpamReg_IPCountry
{
	static function getJsonPropertyFromUrl($url, $property)
	{
		$ctx = stream_context_create(array(
			'http' => array(
				'header'  => implode(array('Connection: close'), "\r\n"),
				'method'  => 'GET',
				'content' => '',
				'timeout' => .5,
			),
		));
		try
		{
			$data = file_get_contents($url, false, $ctx);
			if ($property)
			{
				$data=json_decode($data);
				if (isset($data) && isset($data->property) && $data->property != '')
					return $data->property;
			}
			else
				return $data;
		}
		catch(Exception $e) {}
		return null;
	}

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

        $methods = XenForo_Application::getOptions->TPUDetectSpamRegASMethods;
        if (empty($methods))
        {
            $methods = array(
                array('url'=> 'http://ipinfo.io/%s/country', 'property' => '', 'enable'=>1),
                array('url'=> 'http://ip-api.com/json/%s', 'property' => 'countryCode', 'enable'=>1),
                array('url'=> 'http://api.hostip.info/country.php?ip=/%s', 'property' => '', 'enable'=>1),
                array('url'=> 'https://freegeoip.net/json/%s', 'property' => 'country_code', 'enable'=>0),
            );
        }

		foreach($methods as $method)
		{
			if (empty($method['enable'])) continue;
			$url = sprintf($method['url'], $ip);
			$country = self::getJsonPropertyFromUrl($url, $method['property']);
			if (empty($country))
				continue;
			$country = strtoupper(trim($country));
			if ($country == 'XX' || empty($country))
				continue;
			if ($country)
				return $country;
		}

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