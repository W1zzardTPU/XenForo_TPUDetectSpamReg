<?php

class TPUDetectSpamReg_EmailLength
{
	static function getRegSpamScore(&$score, array $user, $verbose, $debug, $model)
	{
		$o=XenForo_Application::getOptions();

		$items=explode('@', $user['email']);
		$email=array_shift($items);

		if (trim($o->TPUDetectSpamRegEmailLen20)!=0)
		{
			if (strlen($email)>=20)
			{
				$model->logScore('tpu_detectspamreg_emaillen_fail', $o->TPUDetectSpamRegEmailLen20, array('length'=>20, 'email'=>$email));
				$score['points']+=$o->TPUDetectSpamRegEmailLen20;
				return;
			} elseif ($debug)
					$model->logScore('tpu_detectspamreg_emaillen_ok', 0, array('length'=>20, 'email'=>$email));
		}

		if (trim($o->TPUDetectSpamRegEmailLen15)!=0)
		{
			if (strlen($email)>=15)
			{
				$model->logScore('tpu_detectspamreg_emaillen_fail', $o->TPUDetectSpamRegEmailLen15, array('length'=>15, 'email'=>$email));
				$score['points']+=$o->TPUDetectSpamRegEmailLen15;
				return;
			} elseif ($debug)
					$model->logScore('tpu_detectspamreg_emaillen_ok', 0, array('length'=>15, 'email'=>$email));
		}
	}
}
