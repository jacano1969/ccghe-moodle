<?php

/**
* Authentication Plugin: External Database Authentication
 *
 * Checks against an external database.
 *
 * @package    auth
 * @subpackage ccghe_sso
 * @author     Tom Durocher
 * @license    http://www.gnu.org/copyleft/gpl.html GNU Public License
 */
// testing git
defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir.'/authlib.php');
require_once($CFG->libdir.'/adodb/adodb.inc.php');

/**
 * External database authentication plugin.
 */
class auth_plugin_ccghe_sso extends auth_plugin_base
{
     /*
     * The fields we can lock and update from/to external authentication backends
     */
    var $userfields = array(
		'idnumber',
        'firstname',
        'lastname',
        'gender',
        'email',
        'city',
        'province',
        'country',
        'how_heard_detail',
        'profession',
        'icq', // use for title
        'lang',
        'education'
         // the rest are not currently used
//        'description',
//        'url',
//        'institution',
//        'department',
//        'address'
    );

   /**
     * Constructor.
     */
    function auth_plugin_ccghe_sso()
    {
        $this->authtype = 'ccghe_sso';
        $this->config = get_config('auth/ccghe_sso');
        if (empty($this->config->extencoding))
        {
            $this->config->extencoding = 'utf-8';
        }
    }

    /**
     * Returns true if this authentication plugin is "internal".
     *
     * Internal plugins use password hashes from Moodle user table for authentication.
     *
     * @return bool
     */
    function is_internal() {
        //override if needed
        return false;
    }

    function drupal_authentication()
    {
	//	ob_start();
//debugging("here");
         global $CFG, $DB;
        // not all drupal auth is from Main
        $SESSION->isSSO = FALSE;
        
    // if we're already  logged in, this doesn't matter.
    if (isloggedin()) {
        return false;
    }
    // gotta login to Main first, a Rule there will send us back here after
    // note the SSOTOKEN cookie is not currently used
//    if (!isset($_COOKIE['MOODLEUSERNAME']) || !isset($_COOKIE['MOODLESSOTOKEN'])) 
//      return;
    
    $username = $_COOKIE['MOODLEUSERNAME'];
    $DB->set_field('user', 'auth', 'ccghe_sso', array('username' => $username));
    $user->auth = 'ccghe_sso';

    global $SESSION;
    if (!$user = authenticate_user_login($username, $_COOKIE['MOODLESSOTOKEN'])) 
    {
        $SESSION->isSSO = FALSE;
        return;
    }
    else
    {
         $SESSION->isSSO = TRUE;
   }
    
 //   $domain = 'localhost';
    // if we've got this far, we've authenticated them!
    global $USER;
    global $CFG;
    $USER = $user;
    add_to_log(SITEID, 'user', 'drupal login', "view.php?id=$USER->id&course=".SITEID, $USER->id, 0, $USER->id);


    update_user_login_times();
    set_moodle_cookie($USER->username);
    set_login_session_preferences();

    /// This is what lets the user do anything on the site :-)
    load_all_capabilities();

     // redirect
    if (isset($SESSION->wantsurl) and
       (strpos($SESSION->wantsurl, $CFG->wwwroot) == 0) )
    {
            // the URL is set and within Moodle's environment
            $urltogo = $SESSION->wantsurl;
            unset($SESSION->wantsurl);
     }
     else
     {
        // no wantsurl stored or external link. Go to homepage.
        $urltogo = $CFG->wwwroot.'/';
        unset($SESSION->wantsurl);
      }
      redirect($urltogo);
    return true;
}
    
function prelogout_hook() {
        global $USER; // use $USER->auth to find the plugin used for login
				//occurs AFTER loginpage_hook
}
    
function edit_profile_url() {

    global $USER, $DB, $CFG;
	$drupal_uid = $DB->get_field('user', 'idnumber', array('username' => $USER->username));

    return "$CFG->alternateloginurl/"."$drupal_uid/edit";
}

function loginpage_hook() 
{
	$this->drupal_authentication();
}
    /**
     * Returns true if the username and password work and false if they are
     * wrong or don't exist.
     *
     * @param string $username The username (with system magic quotes)
     * @param string $password The password (with system magic quotes)
     *
     * @return bool Authentication success or failure.
     */
    function user_login($username, $password) 
	{
        

        $extusername = textlib::convert($username, 'utf-8', $this->config->extencoding);
        $extpassword = textlib::convert($password, 'utf-8', $this->config->extencoding);

        $authdb = $this->db_init();
				
        $rs = $authdb->Execute("SELECT * FROM {$this->config->table}
                                     WHERE {$this->config->fielduser} = '".$this->                                    ext_addslashes($extusername)."' ");
        if (!$rs) 
		{
        	$authdb->Close();
       		// user does not exist externally
         	return false;
        }		
        if (($rs->EOF) || (!$rs->fields['uid']))
        {
            $rs->Close();
            $authdb->Close();
            // user does not exist externally
            return false;
        }

        // user exists exterally so check password
//        $row =  $rs->FetchObj();
//		    $isValidPass = $extpassword == $row->pass;
        	$authdb->Close();
				$rs->Close();
//        if ($isValidPass)
//				{
    $domain = 'localhost';
	$res = setcookie("DRUPAL_SSO_USER", $extusername, time()+60*60*24*30, '/', '.'.$domain);
	return true;
//				}
}

    function db_init() {
        // Connect to the external database (forcing new connection)
        $authdb = ADONewConnection($this->config->type);
        if (!empty($this->config->debugauthdb)) {
            $authdb->debug = true;
            ob_start();//start output buffer to allow later use of the page headers
        }
        $authdb->Connect($this->config->host, $this->config->user, $this->config->pass, $this->config->name, true);
        $authdb->SetFetchMode(ADODB_FETCH_ASSOC);
        if (!empty($this->config->setupsql)) {
            $authdb->Execute($this->config->setupsql);
        }

        return $authdb;
    }
    /**
     * retuns user attribute mappings between moodle and ldap
     *
     * @return array
     */
    function db_attributes() {
        $moodleattributes = array();
        foreach ($this->userfields as $field) {
            if (!empty($this->config->{"field_map_$field"})) {
                $moodleattributes[$field] = $this->config->{"field_map_$field"};
            }
        }
        $moodleattributes['username'] = $this->config->fielduser;
        return $moodleattributes;
    }

    function logoutpage_hook() {
         global $redirect; // can be used to override redirect after logout

        $domain = 'localhost';
    //    $domain = 'localhost';
        $res = setcookie("DRUPAL_SSO_USER", '', 0, '/', '.'.$domain);
    //print_r($_COOKIE); exit;
        if (!isset($_COOKIE['MOODLEUSERNAME']) || !isset($_COOKIE['MOODLESSOTOKEN'])) 
            $redirect = "http://localhost/ccghe_main";
        else
        {
            $redirect = "http://localhost/ccghe_main/user/logout";
            // just in case Main didn't do it for some unknown reason....
            setcookie('MOODLESSOTOKEN', '', 0, '/', '.'. $domain);
            setcookie('MOODLEUSERNAME', '', 0, '/', '.'. $domain);
        }
        return;
    }
    
function ccghe_save_profile_image($main_uid, $id) {

 require_once('../lib/gdlib.php');
 //  $destination = create_profile_image_destination($id, 'user');
 //   if ($destination === false) {
 //       return false;
  //  }
//    return process_profile_image('/home/admin/public_html/ccghe_main/sites/default/files/pictures/picture-'.$main_uid.'.jpg', $destination);
//    return process_profile_image('/home/cmalamed/public_html/ccghe_main/sites/default/files/pictures/picture-'.$main_uid.'.jpg', $destination);
/*    return process_profile_image('/public_html/Users/tdurocher/Sites/ccghe_main/sites/default/files/pictures/picture-'.$main_uid.'.jpg', $destination);
*/
     $context = get_context_instance(CONTEXT_USER, $id);
    return process_new_icon($context, 'user', 'icon', 0, '/Users/tdurocher/Sites/ccghe_main/sites/default/files/pictures/picture-'.$main_uid.'.jpg');

}
function ccghe_update_picture($main_uid, $uid) {
    global $CFG, $DB;

//        $location = make_user_directory($usernew->id, true);
//        @remove_dir($location);
//        $DB->set_field('user', 'picture', 0, 'id', $usernew->id);
    if ($this->ccghe_save_profile_image($main_uid, $uid))
    $DB->set_field('user', 'picture', 1, array('id'=> $uid));
 }

/**
     * Reads any other information for a user from external database,
     * then returns it in an array
     *
     * @param string $username (with system magic quotes)
     *
     * @return array without magic quotes
     */
    function get_userinfo($username) {

        global $CFG, $DB;

        $textlib = textlib_get_instance();
        $extusername = $textlib->convert($username, 'utf-8', $this->config->extencoding);

        $authdb = $this->db_init();

        $result = array();
         $prep_username = $this->ext_addslashes($extusername);
        // first get uid
        $sql = "select uid, picture from users where name='$prep_username'";
        $rs = $authdb->Execute($sql);
        $fields_obj =  $rs->FetchObj();
        $uid = $fields_obj->uid;
				$result['idnumber'] = $uid;
        if ($fields_obj->picture)
        {
            $moodle_uid = $DB->get_field('user', 'id', array('username' => $username));
            $this->ccghe_update_picture($uid, $moodle_uid);
        }
        // get fields to update

        $sql = "select language FROM users WHERE uid = '$uid'";
        if ($rs = $authdb->Execute($sql))
        {
            if (!$rs->EOF)
            {
                $fields_obj =  $rs->FetchObj();
                $result['lang'] = $fields_obj->language;
             }
             $rs->Close();
        }
       $sql = "select mail FROM users WHERE uid = '$uid'";
        if ($rs = $authdb->Execute($sql))
        {
            if (!$rs->EOF)
            {
                $fields_obj =  $rs->FetchObj();
                $result['email'] = $fields_obj->mail;
             }
             $rs->Close();
        }
        $sql = "select field_first_name_value FROM field_data_field_first_name WHERE entity_id = '$uid'";
        if ($rs = $authdb->Execute($sql))
        {
            if (!$rs->EOF)
            {
                $fields_obj =  $rs->FetchObj();
                $result['firstname'] = utf8_encode($fields_obj->field_first_name_value);
             }
             $rs->Close();
        }
        $sql = "select field_last_name_value FROM field_data_field_last_name WHERE entity_id = '$uid'";
        if ($rs = $authdb->Execute($sql))
        {
            if (!$rs->EOF)
            {
                $fields_obj =  $rs->FetchObj();
                $result['lastname'] = utf8_encode($fields_obj->field_last_name_value);
             }
             $rs->Close();
        }
       $sql = "select field_city_value FROM field_data_field_city WHERE entity_id = '$uid'";
        if ($rs = $authdb->Execute($sql))
        {
            if (!$rs->EOF)
            {
                $fields_obj =  $rs->FetchObj();
                $result['city'] = utf8_encode($fields_obj->field_city_value);
             }
             $rs->Close();
        }
        $sql = "select field_province_value FROM field_data_field_province WHERE entity_id = '$uid'";
        if ($rs = $authdb->Execute($sql))
        {
            if ( !$rs->EOF )
            {
                $fields_obj =  $rs->FetchObj();
                $result['province'] = utf8_encode($fields_obj->field_province_value);
             }
             $rs->Close();
        }
       $sql = "select field_country_value FROM field_data_field_country WHERE entity_id = '$uid'";
        if ($rs = $authdb->Execute($sql))
        {
            if ( !$rs->EOF )
            {
                $fields_obj =  $rs->FetchObj();
                 $result['country'] = utf8_encode($fields_obj->field_country_value);
             }
             $rs->Close();
        }
       $sql = "select field_education_value FROM field_data_field_education WHERE entity_id = '$uid'";
        if ($rs = $authdb->Execute($sql))
        {
            if ( !$rs->EOF )
            {
                $fields_obj =  $rs->FetchObj();
                 $result['education'] = $fields_obj->field_education_value;
             }
             $rs->Close();
        }
       $sql = "select field_profession_value FROM field_data_field_profession WHERE entity_id = '$uid'";
        if ($rs = $authdb->Execute($sql))
        {
            if ( !$rs->EOF )
            {
                $fields_obj =  $rs->FetchObj();
                 $result['profession'] = $fields_obj->field_profession_value;
             }
             $rs->Close();
        }
       $sql = "select field_gender_value FROM field_data_field_gender WHERE entity_id = '$uid'";
        if ($rs = $authdb->Execute($sql))
        {
            if ( !$rs->EOF )
            {
                $fields_obj =  $rs->FetchObj();
                $result['gender'] = strtolower($fields_obj->field_gender_value);
             }
             $rs->Close();
        }
       $sql = "select field_how_hear_value FROM field_data_field_how_hear WHERE entity_id = '$uid'";
        if ($rs = $authdb->Execute($sql))
        {
            if ( !$rs->EOF )
            {
                $fields_obj =  $rs->FetchObj();
                $result['how_heard_detail'] = utf8_encode($fields_obj->field_how_hear_value);
             }
             $rs->Close();
        }
       $sql = "select field_title_value FROM field_data_field_title WHERE entity_id = '$uid'";
        if ($rs = $authdb->Execute($sql))
        {
            if ( !$rs->EOF )
            {
                $fields_obj =  $rs->FetchObj();
                 $result['icq'] = utf8_encode($fields_obj->field_title_value);
             }
             $rs->Close();
        }
            
        $authdb->Close();
        return $result;

    }

    function user_exists($username) {

    /// Init result value
        $result = false;

        $extusername = textlib::convert($username, 'utf-8', $this->config->extencoding);

        $authdb = $this->db_init();

        $rs = $authdb->Execute("SELECT * FROM {$this->config->table}
                                     WHERE {$this->config->fielduser} = '".$this->ext_addslashes($extusername)."' ");

        if (!$rs) {
            print_error('auth_dbcantconnect','auth_ccghe_sso');
        } else if ( !$rs->EOF ) {
            // user exists exterally
            $result = true;
        }

        $authdb->Close();
        return $result;
    }


    function get_userlist() {

    /// Init result value
        $result = array();

        $authdb = $this->db_init();

        // fetch userlist
        $rs = $authdb->Execute("SELECT {$this->config->fielduser} AS username
                                FROM   {$this->config->table} ");

        if (!$rs) {
            print_error('auth_dbcantconnect','auth_ccghe_sso');
        } else if ( !$rs->EOF ) {
         //trd   while ($rec = rs_fetch_next_record($rs)) {
            foreach ($rs as $rec) {
                $rec = (object)array_change_key_case((array)$rec , CASE_LOWER);
                array_push($result, $rec->username);
            }
        }
        $rs->close();
        $authdb->Close();
        return $result;
    }

    /**
     * reads userinformation from DB and return it in an object
     *
     * @param string $username username (with system magic quotes)
     * @return array
     */
    function get_userinfo_asobj($username) {
        $user_array = $this->get_userinfo($username);
        $user = new stdClass();
        foreach($user_array as $key=>$value) {
            $user->{$key} = $value;
        }
        return $user;
    }

    /**
     * will update a local user record from an external source.
     * is a lighter version of the one in moodlelib -- won't do
     * expensive ops such as enrolment
     *
     * If you don't pass $updatekeys, there is a performance hit and
     * values removed from DB won't be removed from moodle.
     *
     * @param string $username username
     * @param bool $updatekeys
     * @return stdClass
     */
    function update_user_record($username, $updatekeys=false) {
        global $CFG, $DB;

        //just in case check text case
        $username = trim(textlib::strtolower($username));

        // get the current user record
        $user = $DB->get_record('user', array('username'=>$username, 'mnethostid'=>$CFG->mnet_localhost_id));
        if (empty($user)) { // trouble
            error_log("Cannot update non-existent user: $username");
            print_error('auth_dbusernotexist','auth_ccghe_sso',$username);
            die;
        }

        // Ensure userid is not overwritten
        $userid = $user->id;

        if ($newinfo = $this->get_userinfo($username)) {
            if (empty($updatekeys)) { // all keys? this does not support removing values
                $updatekeys = array_keys($newinfo);
            }

            foreach ($updatekeys as $key) {
                if (isset($newinfo[$key])) {
                    $value = $newinfo[$key];
                } else {
                    $value = '';
                }

                if (!empty($this->config->{'field_updatelocal_' . $key})) {
                    if (isset($user->{$key}) and $user->{$key} != $value) { // only update if it's changed
                        $DB->set_field('user', $key, $value, array('id'=>$userid));
                    }
                }
            }
        }
        return $DB->get_record('user', array('id'=>$userid, 'deleted'=>0));
    }



    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * @param array $page An object containing all the data for this page.
     */
    // $user_fields same as this->$userfields 
    function config_form($config, $err, $user_fields) {
        include 'config.html';
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     */
    function process_config($config) {
        // set to defaults if undefined
        if (!isset($config->host)) {
            $config->host = 'localhost';
        }
        if (!isset($config->type)) {
            $config->type = 'mysql';
        }
        if (!isset($config->sybasequoting)) {
            $config->sybasequoting = 0;
        }
        if (!isset($config->name)) {
            $config->name = '';
        }
        if (!isset($config->idnumber)) {
            $config->idnumber = 0;
        }
        if (!isset($config->user)) {
            $config->user = '';
        }
        if (!isset($config->pass)) {
            $config->pass = '';
        }
        if (!isset($config->table)) {
            $config->table = 'users';
        }
        if (!isset($config->fielduser)) {
            $config->fielduser = 'name';
        }
        if (!isset($config->fieldpass)) {
            $config->fieldpass = 'pass';
        }
        if (!isset($config->passtype)) {
            $config->passtype = 'plaintext';
        }
        if (!isset($config->extencoding)) {
            $config->extencoding = 'utf-8';
        }
        if (!isset($config->setupsql)) {
            $config->setupsql = '';
        }
        if (!isset($config->debugauthdb)) {
            $config->debugauthdb = 0;
        }
        if (!isset($config->removeuser)) {
            $config->removeuser = 0;
        }
        if (!isset($config->changepasswordurl)) {
            $config->changepasswordurl = '';
        }

        // save settings
        set_config('host',          $config->host,          'auth/ccghe_sso');
        set_config('type',          $config->type,          'auth/ccghe_sso');
        set_config('sybasequoting', $config->sybasequoting, 'auth/ccghe_sso');
        set_config('name',          $config->name,          'auth/ccghe_sso');
        set_config('user',          $config->user,          'auth/ccghe_sso');
        set_config('pass',          $config->pass,          'auth/ccghe_sso');
        set_config('table',         $config->table,         'auth/ccghe_sso');
        set_config('fielduser',     $config->fielduser,     'auth/ccghe_sso');
        set_config('fieldpass',     $config->fieldpass,     'auth/ccghe_sso');
        set_config('passtype',      $config->passtype,      'auth/ccghe_sso');
        set_config('extencoding',   trim($config->extencoding), 'auth/ccghe_sso');
        set_config('setupsql',      trim($config->setupsql),'auth/ccghe_sso');
        set_config('debugauthdb',   $config->debugauthdb,   'auth/ccghe_sso');
        set_config('removeuser',    $config->removeuser,    'auth/ccghe_sso');
        set_config('changepasswordurl', trim($config->changepasswordurl), 'auth/ccghe_sso');

        return true;
    }

    function ext_addslashes($text) {
        // using custom made function for now
        if (empty($this->config->sybasequoting)) {
            $text = str_replace('\\', '\\\\', $text);
            $text = str_replace(array('\'', '"', "\0"), array('\\\'', '\\"', '\\0'), $text);
        } else {
            $text = str_replace("'", "''", $text);
        }
        return $text;
    }
}

