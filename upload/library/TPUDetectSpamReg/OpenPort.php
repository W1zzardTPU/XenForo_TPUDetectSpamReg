<?php

class TPUDetectSpamReg_OpenPort
{
	const TIMEOUT=3;
	
	static function isIPv6($ip) 
	{
		return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
	}
		
	static function getRegSpamScore(&$score, array $user, $verbose, $debug, $model)
	{
		$o=XenForo_Application::getOptions();

		if (trim($o->TPUDetectSpamRegOpenPort)!='')
  	{
  		if (!function_exists('socket_create'))
  		{
  			$model->logScore('PHP function socket_create() not available, you need the PHP socket extension for open port detection to work', 0);
  			return;
  		}
  		
  		$entries=array();
  		$socks=array();
  		foreach (explode("\n", $o->TPUDetectSpamRegOpenPort) as $entry)
  		{
				$entry=explode('|', trim($entry));
  			if (count($entry)!=2)
  				continue;

  			list($points, $port)=$entry;

  			if (!is_numeric($port))
  				$port=getservbyname($port, 'tcp');

  			if ($port>0)
  			{
  				socket_clear_error();

  				if (self::isIPv6($user['ip']))
  				{
	  				$sock=socket_create(AF_INET6, SOCK_STREAM, SOL_TCP);
  				} else
  				{
	  				$sock=socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
  				}

					socket_set_nonblock($sock);
 					@socket_connect($sock, $user['ip'], $port);
 					
 					$errno=socket_last_error();
					if (($errno==SOCKET_EALREADY) || ($errno==SOCKET_EINPROGRESS) || ($errno==0))
						$socks[]=$sock;
					else
						socket_close($sock);

    			$entries[]=array('points'=>$points, 'port'=>$port, 'open'=>false);
  			}
  		}

  		$start=microtime(true);
  		while (($socks) && (microtime(true)-$start<self::TIMEOUT))
  		{
				$null=null;
  			$write=$socks;
  			socket_select($null, $write, $null, 1);
  			foreach ($write as $k=>$sock)
  			{
					$errno=socket_get_option($sock, SOL_SOCKET, SO_ERROR);

      		if ($errno==0)
      		{
      			$entries[$k]['open']=true;
      		} elseif ($errno==SOCKET_ECONNREFUSED)
      		{
      		} elseif ($errno==SOCKET_ETIMEDOUT)
      		{
      		} else
      		{
          	$errmsg=socket_strerror($errno);
      		}

     			unset($socks[$k]);
      		socket_close($sock);
  			}
  		}

  		foreach ($entries as $entry)
  		{
  			if ($entry['open'])
  			{
      		$model->logScore('tpu_detectspamreg_port_fail', $entry['points'], array('port'=>$entry['port']));
      		$points = $entry['points'];
  				if (is_numeric($points))
  					$score['points']+=$points;
  				else
  					$score[$points]=true;
      	} else
      	{
      		if ($debug)
      			$model->logScore('tpu_detectspamreg_port_ok', 0, array('port'=>$entry['port']));
      	}
  		}
  	}
	}
}