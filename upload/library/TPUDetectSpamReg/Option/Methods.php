<?php

class TPUDetectSpamReg_Option_Methods
{
    public static function assembleItem(array &$values, array &$item = null, &$itemState, $expectedItemState, $key, $value)
    {
        if (isset($value[$key]))
        {
            if ($item === null)
            {
                $item = array();
                $itemState = $expectedItemState;
            }
            if ($itemState == $expectedItemState)
            {
                $item[$key] = $value[$key];
                $itemState++;
            }
            else
            {
                $values[] = $item;
                $item = null;
                $itemState = 0;
            }
        }
        else if ($item !== null && !isset($item[$key]))
        {
            $item[$key] = '';
        }
    }

    public static function verifyOption(array &$values, XenForo_DataWriter $dw, $fieldName)
    {
        if (isset($values['new']))
        {
            $newItems = $values['new'];
            unset($values['new']);
            // some assembly required
            if (!empty($newItems))
            {
                $itemState = 0;
                $item = null;
                print "<pre>";
                foreach($newItems as $value)
                {
                    self::assembleItem($values, $item, $itemState, 0, 'enable', $value);
                    self::assembleItem($values, $item, $itemState, 1, 'url', $value);
                    self::assembleItem($values, $item, $itemState, 2, 'property', $value);
                }

                if ($item !== null)
                {
                    $values[] = $item;
                }
                var_dump($values);
                var_dump($item);
                print "</pre>";
                //throw new Exception(1);
            }
        }
        foreach($values as $key => &$value)
        {
            if (empty($value))
            {
                unset($values[$key]);
            }
        }
        return true;

/*

        $permissionModel = XenForo_Model::create('XenForo_Model_Permission');
        $permissionsGrouped = $permissionModel->getAllPermissionsGrouped();
        $group = 'forum';
        $permissions = $permissionsGrouped[$group];
        $options = array();
        foreach ($permissions AS $permissionName => $permission)
        {
            if ($permission['interface_group_id'] != 'forumPermissions' && $permission['interface_group_id'] != 'CollaborativeThreads')
            {
                unset($permissions[$permissionName]);
            }
        }

        // pull out new items and re-insert in the correct format, and that it is formated correctly
        foreach($values as $key => $value)
        {
            if (is_numeric($key))
            {
                $values[$value] = true;
                unset($values[$key]);
            }
            else
            {
                $values[$key] = true;
            }
        }

        foreach($values as $key => $value)
        {
            if (!isset($permissions[$key]) || empty($value))
            {
                unset($values[$key]);
            }
        }

        ksort($values);
*/
        return true;
    }
}
