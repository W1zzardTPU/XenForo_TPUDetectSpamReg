<?php

class TPUDetectSpamReg_ModelSpamPrevention extends XFCP_TPUDetectSpamReg_ModelSpamPrevention
{
	const TPURESULT_ALLOWED = 'allowed';
	const TPURESULT_MODERATED = 'moderated';
	const TPURESULT_MODERATEPOSTS = 'moderateposts';
	const TPURESULT_DENIED = 'denied';

	public static $moderateAllPosts=false;

	public function logScore($phrase, $score, $data=array())
	{
		$data['reason']=$phrase;

		if (is_numeric($score))
			$data['score']=sprintf('%+d', $score);
		else
			$data['score']='+'.$score;

		$this->_resultDetails[] = array(
			'phrase' => $phrase,
			'data' => $data
		);
	}

	public function querySfs($user)
	{
		$apiUrl=$this->_getSfsApiUrl(array('username'=>$user['username'], 'email'=>$user['email'], 'ip'=>$user['ip']));

		$apiResponse=false;

		$client = XenForo_Helper_Http::getClient($apiUrl);
		try
		{
			$response=$client->request('GET');
			$body=$response->getBody();

			$apiResponse=$this->_decodeSfsApiData($body);
		}	catch (Zend_Http_Exception $e) {}

			return $apiResponse;
		}

		public function buildWildcardRegex($s)
		{
			$s=preg_quote($s);
			$s=str_replace('\*', '.*', $s);
			$s=str_replace('\?', '.', $s);

			return $s;
		}

		public function allowRegistration(array $user, Zend_Controller_Request_Http $request)
		{
			$result=parent::allowRegistration($user, $request);

			$user['ip']=$_SERVER['REMOTE_ADDR'];

			$o=XenForo_Application::getOptions();

			if ($o->TPUDetectSpamRegVerbose)
			$this->logScore('tpu_detectspamreg_checking', 0, array('username'=>$user['username'], 'email'=>$user['email'], 'ip'=>$user['ip']));

			$score=array('points'=>0);

			XenForo_CodeEvent::fire('tpu_detect_spam_reg', array(&$score, $user, $o->TPUDetectSpamRegVerbose, $o->TPUDetectSpamRegDebug, $this));

			if ($o->TPUDetectSpamRegVerbose)
			$this->logScore('tpu_detectspamreg_totalscore', $score['points']);

			$action=self::TPURESULT_ALLOWED;

			if ($o->TPUDetectSpamRegScoreRej>0)
			{
				if ($score['points']>=$o->TPUDetectSpamRegScoreRej)
				{
					$this->logScore('tpu_detectspamreg_fail_rej', $score['points'], array('required'=>$o->TPUDetectSpamRegScoreRej));
					$action=self::TPURESULT_DENIED;
				}
			}

			if ($action==self::TPURESULT_ALLOWED)
			{
				if ($o->TPUDetectSpamRegScoreMod>0)
				{
					if ($score['points']>=$o->TPUDetectSpamRegScoreMod)
					{
						$this->logScore('tpu_detectspamreg_fail_mod', $score['points'], array('required'=>$o->TPUDetectSpamRegScoreMod));
						$action=self::TPURESULT_MODERATED;
					}
				}
			}

			if ($action==self::TPURESULT_ALLOWED)
			{
				if ($o->TPUDetectSpamRegScoreModPosts['score']>0)
				{
					if ($score['points']>=$o->TPUDetectSpamRegScoreModPosts['score'])
					{
						$this->logScore('tpu_detectspamreg_fail_modposts', $score['points'], array('required'=>$o->TPUDetectSpamRegScoreModPosts['score']));
						$action=self::TPURESULT_MODERATEPOSTS;
					}
				}
			}

			if ((isset($score['reject']) && ($score['reject'])))
			{
				$this->logScore('Rejected. Direct rule selection triggered', 0);
				$action=self::TPURESULT_DENIED;
			} elseif ((isset($score['moderate']) && ($score['moderate'])))
				{
					if ($action!=self::TPURESULT_DENIED)
					{
						$this->logScore('Moderated. Direct rule selection triggered', 0);
						$action=self::TPURESULT_MODERATED;
					}
				} elseif ((isset($score['moderateposts']) && ($score['moderateposts'])))
					{
						if (($action!=self::TPURESULT_DENIED) && ($action!=self::TPURESULT_MODERATED))
						{
							$this->logScore('New Posts Moderated. Direct rule selection triggered', 0);
							$action=self::TPURESULT_MODERATEPOSTS;
						}
					}

			if ($action==self::TPURESULT_DENIED)
				$result=self::RESULT_DENIED;
			elseif (($result==self::RESULT_ALLOWED) && ($action==self::TPURESULT_MODERATED))
				$result=self::RESULT_MODERATED;

			if ($action==self::TPURESULT_MODERATEPOSTS)
				self::$moderateAllPosts=true;

			$this->_lastResult=$result;
			return $result;
		}

		public function logSpamTrigger($contentType, $contentId, $result=null, array $details=null, $userId=null, $ipAddress=null)
		{
			if ($result === null)
			{
				$result = $this->getLastCheckResult();
			}

			$hax=false;
			if ($result==self::RESULT_ALLOWED)
			{
				$result=self::RESULT_MODERATED;
				$hax=true;
			}

			$return=parent::logSpamTrigger($contentType, $contentId, $result, $details, $userId, $ipAddress);

			if ($hax)
				$this->_getDb()->query('UPDATE xf_spam_trigger_log SET result="allowed" WHERE log_date=? AND result=? AND ip_address=?', array(XenForo_Application::$time, self::RESULT_MODERATED, XenForo_Helper_Ip::getBinaryIp(null, $ipAddress)));

			return $return;
		}

		public function checkMessageSpam($content, array $extraParams=array(), Zend_Controller_Request_Http $request=null)
		{
			$result=parent::checkMessageSpam($content, $extraParams, $request);

			if (XenForo_Visitor::getInstance()->hasPermission('general', 'TPUSpamRegModAllPosts'))
			{
				if (($request!==null) && (strpos($request->getRequestUri(), '/conversations/')!==false))	// Allow private messages
				{
					return $result;
				}

				$o=XenForo_Application::getOptions();

				if ($o->TPUDetectSpamRegScoreModPosts['messagecount']>0)
				{
					if (XenForo_Visitor::getInstance()->get('message_count')>$o->TPUDetectSpamRegScoreModPosts['messagecount'])
					{
						$permissions=array('general'=>array('TPUSpamRegModAllPosts'=>'unset'));
						$this->getModelFromCache('XenForo_Model_Permission')->updateGlobalPermissionsForUserCollection($permissions, 0, XenForo_Visitor::getInstance()->getUserId());

						return $result;
					}
				}

				return XenForo_Model_SpamPrevention::RESULT_MODERATED;
			}

			return $result;
		}
	}
