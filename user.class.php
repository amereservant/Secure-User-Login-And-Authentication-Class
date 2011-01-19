<?php
if(!defined('DEBUG')) define('DEBUG', true);

// Database Settings (These SHOULD be set somewhere else!)
    
    // MySQL
if(!defined('DB_HOST')) define('DB_HOST', ''); // Database Host Name
if(!defined('DB_USER')) define('DB_USER', ''); // Database Username
if(!defined('DB_PASS')) define('DB_PASS', ''); // Database Password
if(!defined('DB_NAME')) define('DB_NAME', ''); // Database Name

    // SQLite
if(!defined('SQLITE_FILE')) define('SQLITE_FILE', './test.sdb'); // SQLite Filename and path

// Session Security Constants
define('_SESSION_SALT', $_SERVER['HTTP_HOST']);
define('_SESSION_NAME', preg_replace('#[^a-z0-9]#i', '', $_SERVER['HTTP_HOST']));
define('_SESSION_DIR', str_replace('.', '_', $_SERVER['HTTP_HOST']) . '_sessiondata');

/**
 * Secure User Login And Authentication Class
 *
 * This is a user authentication and login class that utilizes php sessions and creates
 * a secure session for storing the user's login status and any other session data.
 * It also allows for persistent login support by utilizing session cookies.
 *
 * It includes a vigorous user password encryption method as well.
 *
 * Requires PHP5 >= 5.1 
 *
 * @license     http://creativecommons.org/licenses/MIT/ MIT
 * @category    authentication
 * @package     Secure User Sessions
 * @author      David Miles <david@amereservant.com>
 * @link        https://github.com/amereservant/Secure-User-Login-And-Authentication-Class
 * @version     1.0
 * @since       1.0 (January 14, 2011)
 */

/**
 * Authentication Class
 */
class userAuth extends PDO
{
   /**
    * Secure Word - (This should be changed for security reasons!)
    *
    * @var      string
    * @access   private
    * @since    1.0
    */
    private $_secure_word = 'SECUREDSALT_';

   /**
    * Use User Agent
    *
    * @var      bool
    * @access   private
    * @since    1.0
    */
    private $_use_user_agent = true;
    
   /**
    * IP Block Length (change this to add extra session securty)
    *
    * @param    integer
    * @access   private
    * @since    1.0
    */
    private $_ip_block_length = 4;
    
   /**
    * Algorithm
    *
    * @var      string
    * @access   private
    * @since    1.0
    */
    private $_algorithm;
   
   /**
    * Is SQLite Database Object
    * @var      bool
    * @access   private
    * @since    1.0
    */
    private $_is_sqlite;
    
   /**
    * Cookie Name
    *
    * @var      string
    * @access   private
    * @since    1.0
    */
    private $_cookie_name = 'tcUserLogin';
    
   /**
    * Cookie Expiration (in days)
    *
    * @var      integer
    * @access   private
    * @since    1.0
    */
    private $_cookie_expiration_days = 5;
    
   /**
    * Class Constructor
    *
    * The class constructor checks if the param $dbh is an instance of the PDO class and
    * dies if not.  If it is, it will assign it to the {@link $_dbh} (database handle) property.
    *
    * @param    void
    * @return   void
    * @access   public
    * @since    1.0
    */
    public function __construct()
    {
        $this->_session_setup();
        
        $drivers = PDO::getAvailableDrivers();
        try
        {
            // Establish SQLite database ?
            if(strlen(DB_USER) < 1 || strlen(DB_PASS) < 1)
            {
                if(!in_array('sqlite', $drivers) || strlen(SQLITE_FILE) < 1)
                    die('An SQLITE database could not be created because '. (!in_array('sqlite', $drivers) ?
                        ' the `sqlite` driver':' SQLITE_FILE name') .' is not available!');
                
                parent::__construct('sqlite:'.SQLITE_FILE, '', '', array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
            }
            // Establish MySQL database ?
            else
            {
                if(!in_array('mysql', $drivers) || strlen(DB_HOST) < 1 || strlen(DB_NAME) < 1)
                    die('A MySQL database connection could not be established because '. 
                        (!in_array('mysql', $drivers) ? 'the mysql PDO driver is not available':
                        'the database host or database name is empty').'.');
                
                parent::__construct('mysql:dbname='. DB_NAME .';host='. DB_HOST, DB_USER, DB_PASS, 
                    array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
                    
            }
        }
        catch(PDOException $e) {
            die('Connection Failed: '. $e->getMessage());
        }
        $this->_is_sqlite = $this->getAttribute(PDO::ATTR_DRIVER_NAME) == 'sqlite';
    }
    
   /**
    * Encrypt Password
    *
    * This is used when creating a new user.  The database table should be set to store
    * the two salts, the pattern, and the encrypted password.
    * Credit goes to {@link http://microsonic.org/2009/04/05/php-password-salt/} since
    * this function derived from there.
    *
    * @param    string  $password   The password to encrypt
    * @return   array               The array with keys 'salt1', 'salt2', 'password', and 'pattern',
    *                               which are all used by the {@link validate_password()} method 
    *                               to check the password.
    * @access   protected
    * @since    1.0
    */
    protected function encrypt_password( $password )
    {
        // This is our first set of possible salt characters. Shuffle so always different all aspects
        $set1 = str_shuffle("!@#$%^&*()_+=-';:,<.>126AaBbJjKkLlSdDsQwWeErqRtTyY");
        
        // Second set. Same thing, different characters though :D
        $set2 = str_shuffle("1234567890`~ZxzxCcVvBb?[]{}pP");
        
       /**
        * Now the loops to actually make the salt characters
        * We'll be using the rand(); function give us random chars from the shuffled sets
        * The for loops are fairly simple.
        * Salt1 = 12 char
        * Salt2 = 10 char
        */
        $salt1 = '';
        $salt2 = '';
        
        for($i=0;$i<12;$i++)
        {
            $salt1 .= $set1[rand() % strlen($set1)-.04];
        }
            
        for($i=0;$i<10;$i++)
        {
          $salt2 .= $set2[rand() % strlen($set2)-.07];
        }    
        
        // Now let's generate a pattern. We'll have only about 4 combinations.
        $part[1] = "{salt1}";
        $part[2] = "{salt2}";
        $part[3] = "{pass}";
        $psort   = array_rand($part,3);
        $pattern = $part[$psort[0]].".".$part[$psort[1]].".".$part[$psort[2]];

        // Now for pass
        $grep = array( "/{salt1}/", "/{salt2}/", "/{pass}/" ); // Identify pattern
        $repl = array( $salt1, $salt2, $password ); // Make pattern real

        // Now replace the pattern with actual values
        $sendpass = preg_replace( $grep, $repl, $pattern );
        
        return array( 'salt1'    => $salt1, 
                      'salt2'    => $salt2, 
                      'password' => sha1($sendpass),
                      'pattern'  => $pattern );
    }
    
   /**
    * Validate Password
    *
    * This function provides a way to check passwords encrypted with the {@link encrypt_password()}
    * function.
    * Credit goes to {@link http://microsonic.org/2009/04/05/php-password-salt/} since
    * this function derived from there.
    *
    * @param    string      $pass       The password to check (unencrypted)
    * @param    array       $encrypt    The array of encrypted data created by {@link encrypt_password()}
    * @return   bool                    True if the password is valid, false if not.
    * @access   protected
    * @since    1.0
    */
    protected function validate_password( $pass, $encrypt )
    {
        // Use the grep and replace arrays again to replace information from pattern!
        $grep = array( "/{salt1}/", "/{salt2}/", "/{pass}/" );        // Identify pattern
        $repl = array( $encrypt['salt1'], $encrypt['salt2'], $pass ); // Make pattern real
        $pwd  = preg_replace( $grep, $repl, $encrypt['pattern'] );    // Generate password how it should be.

        // Now let's make sure the user is properly identifying!
        if( sha1($pwd) != $encrypt['password'] )
        {
          return false;
        }
        return true;
    }
    
   /**
    * User Login
    *
    * This method checks if the user has provided a valid login.  If the user is arleady
    * logged in, (determined by the {@link validate_uniquekey()} method call), it will
    * return true and avoid the database query.
    *
    * @param    string  $username   The user's login username
    * @param    string  $password   The user's login password
    * @return   bool
    * @access   public
    * @since    1.0
    */
    public function user_login( $username, $password )
    {
        // Check if user is already logged in and return if so
        if($this->validate_uniquekey()) 
            return true;
            
        // Query database for user details
        $stmt = $this->prepare("SELECT id, username, password, pattern, salt1, ".
                               "salt2 FROM users WHERE username=:username");
        $stmt->bindParam(':username', $username, PDO::PARAM_STR, 75);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        
        // User likely doesn't exist
        if(!$result) 
        {
            if(DEBUG) trigger_error('User `'. $username .'` does not exist!', E_USER_WARNING);
            $this->_destroy();
            return false;
        }
        
        // Password doesn't match
        if(!$this->validate_password( trim($password), $result ))
        {
            if(DEBUG) trigger_error('Password for user `'. $username .'` did not validate!', E_USER_WARNING);
            $this->_destroy();
            return false;
        }
        return $this->set_session( $result ); // User is logged in, add to $_SESSION data
    }
    
   /**
    * User Logout
    *
    * Logs the user out by calling the {@link _destroy()} method.  Simple as that.
    *
    * @param    void
    * @return   void
    * @access   public
    * @since    1.0
    */
    public function user_logout()
    {
        $this->_destroy();
    }
    
   /**
    * Is User Logged In
    *
    * This checks the current user's SESSION data to see if the user is logged in and
    * if not, it will return false.
    *
    * @param    void
    * @return   bool        'true' if they are logged in, 'false' if not
    * @access   public
    * @since    1.0
    */
    public function is_logged_in()
    {
        if(!isset($_SESSION['logged_in'], $_SESSION['_UniqueKey']) || $_SESSION['logged_in'] === false)
            return false;
        
        if($this->validate_uniquekey())
            return true;
        else    
            return false;
    }
   
   /**
    * Set Login Session
    *
    * This method sets the session variables for a valid login.  This should be called
    * after login details have been varified, which at this point should only be by the
    * {@link user_login()} method.
    *
    * @param    array           An array containing the user's details.
    * @return   bool            'true' if successful, 'false' if not
    * @access   protected
    * @since    1.0
    */
    protected function set_session( $values )
    {
        $this->_set_session_uniquekey();
        
        $_SESSION['uid']       = $values['id'];
        $_SESSION['username']  = htmlspecialchars($values['username']);
        $_SESSION['logged_in'] = true;
        
        if(!session_id() && DEBUG)
            trigger_error('There is no session id!  Make sure session_start() is being called first!', E_USER_WARNING);
        
        return true;
    }
    
   /**
    * Session Setup
    *
    * This method sets the session security info.  It should be called FIRST and only by
    * the class {@link __construct()} method.
    *
    * @param    void
    * @return   void
    * @access   private
    * @since    1.0
    */
    private function _session_setup()
    {
        if(!isset($_SESSION))
        {
            $dir_path = ini_get("session.save_path") . DIRECTORY_SEPARATOR . _SESSION_DIR;
            if(!is_dir($dir_path)) mkdir($dir_path);
            
            if( ini_get('session.use_trans_sid') == true) {
                ini_set('url_rewriter.tags'     , '');
                ini_set('session.use_trans_sid' , false);
            }
            
            $lifetime = 60 * 60 * 24 * $this->_cookie_expiration_days;
            ini_set('session.gc_maxlifetime'  , $lifetime);
            ini_set('session.gc_divisor'      , '1');
            ini_set('session.gc_probability'  , '1');
            ini_set('session.cookie_lifetime' , '0');
            ini_set('session.save_path', $dir_path);
            session_name(_SESSION_NAME);
            session_start();
        }
        $this->_algorithm = function_exists('hash') && in_array('sha256', hash_algos()) ? 'sha256' : null;
    }
    
   /**
    * Make UniqueKey
    *
    * This creates a unique key for the user that is used to validate the $_SESSION.
    * It combines the {@link $_secure_word} property, the user agent, and however many "blocks"
    * of the IP address specified by the {@link $_ip_block_length} property to form a unique string
    * that is then converted to an encrypted hash.
    *
    * It will be assigned to the $_SESSION['_UniqueKey'] key and used for validating the SESSION.
    * To further secure it, change the value of {@link $_secure_word} to something unique.
    *
    * @param    void
    * @return   string      An encrypted hash either 30(MD5), 40(sha1), or 64(hash) characters long
    *                       depending on which encryption function is used.
    * @access   private
    * @since    1.0
    */
    private function _make_uniquekey()
    {
        $uniquekey = $this->_secure_word;
        if( $this->_use_user_agent )
            $uniquekey .= $_SERVER['HTTP_USER_AGENT'];
        
        // Compile and dissect the user's IP address
        $uniquekey .= implode('.', array_slice(explode('.', $_SERVER['REMOTE_ADDR']), 0, $this->_ip_block_length));
        
        // Fallback to sha1 or md5 if hash() function doesn't exist
        if($this->_algorithm === null)
            return function_exists('sha1') ? sha1($uniquekey) : md5($uniquekey);
        
        return hash($this->_algorithm, $uniquekey);
    }
        
   /**
    * Regenerate Session ID
    *
    * This is used to regenerate the session id.
    * It will delete the old session file automatically.
    *
    * @param    void
    * @return   void
    * @access   private
    * @since    1.0
    */
    private function _regenerate_session_id()
    {
        // I *think* if the parameter is null or false, the session info (such as session filename)
        // can be stored in the database and then restored on successful login.
        session_regenerate_id(true); // Requires PHP => 5.1
    }
    
   /**
    * Set Session UniqueKey
    *
    * @param    void
    * @return   void
    * @access   private
    * @since    1.0
    */
    private function _set_session_uniquekey()
    {
        $this->_regenerate_session_id();
        $_SESSION['_UniqueKey'] = $this->_make_uniquekey();
    }
    
   /**
    * Validate UniqueKey
    *
    * This validates the current uniquekey to ensure it is valid.
    *
    * @param    void
    * @return   bool
    * @access   protected
    * @since    1.0
    */
    protected function validate_uniquekey()
    {
        $this->_regenerate_session_id();
        
        if(isset($_SESSION['_UniqueKey']))
            return $_SESSION['_UniqueKey'] === $this->_make_uniquekey();
        
        if(DEBUG) echo '_UniqueKey is not set!';
        return false;
    }
    
   /**
    * Destroy Session
    *
    * This is used to detroy the user session when called.
    *
    * @param    void
    * @return   void
    * @access   private
    * @since    1.0
    */
    private function _destroy()
    {
        if(isset($_SESSION)) $_SESSION = array();
        if(isset($_COOKIE[session_name()])) setcookie(session_name(), '', time() -40000);
        @session_destroy();
        return;
    }
    
   /**
    * Create New User
    *
    * This method is used to create a new user in the database.  It will create the 
    * 4-part encrypted password and try to create the new user.
    * If the username already exists, it will catch the PDOException and return false
    * or display a message if DEBUG is set to 'true'.
    *
    * @param    string  $username       The username for the new user
    * @param    string  $password       The password (un-encrypted) for the new user
    * @return   bool                    'true' if successfully added, 'false' if not such as
    *                                   the user already exists, etc.
    * @access   public
    * @since    1.0
    */
    public function create_user( $username, $password )
    {
        $username = trim($username); // Remove any extra whitespace
        $password = trim($password);
        if(strlen($username) < 1 || strlen($password) < 1) return false;
        
        extract($this->encrypt_password($password));
        
        try
        {
            $sql = "INSERT INTO users(username, password, pattern, salt1, salt2) VALUES ".
                   "(:username, :password, :pattern, :salt1, :salt2)";
            $stmt = $this->prepare($sql);
            
            $stmt->bindParam(':username', $username, PDO::PARAM_STR, 75);
            $stmt->bindParam(':password', $password, PDO::PARAM_STR, 40);
            $stmt->bindParam(':pattern', $pattern  , PDO::PARAM_STR, 22);
            $stmt->bindParam(':salt1'  , $salt1    , PDO::PARAM_STR, 12);
            $stmt->bindParam(':salt2'  , $salt2    , PDO::PARAM_STR, 10);
            
            $result = $stmt->execute();
        }
        catch(PDOException $e) {
            $msg = $e->getMessage();
            
            if(DEBUG) {
                // Make a pretty message if it's a non-unique error
                if(preg_match('#(not unique)#i', $msg))
                    echo 'That username already exists!';
                else
                    echo $msg;
            }
            return false;
        }
        return $result;
    }
        
   /**
    * Check If Table Exists
    *
    * This method is used to check if a database table already exists or not.
    *
    * @param    string  $table_name     The name of the table to check for
    * @return   bool                    'true' if it does, 'false' if it doesn't
    * @access   protected
    * @since    1.0
    * @TODO     These SHOULD be changed to use prepared statements
    */
    protected function check_table_exists( $table_name )
    {
        // First check if the table already exists
        if( $this->_is_sqlite )
        {
            $sql = "SELECT name FROM sqlite_master WHERE name=:name";
        }
        else
        {
            $sql = "SELECT COUNT(*) AS count FROM information_schema tables WHERE ".
                   "table_schema = ". DB_NAME ." AND table_name=:name";
        }
        
        try {
            $stmt  = $this->prepare($sql);
            $stmt->bindParam(':name', $table_name, PDO::PARAM_STR);
            $stmt->execute();
            $count = strlen($stmt->fetchColumn()); // If count fails with MySQL, change this
        }
        catch(PDOException $e) {
            if(DEBUG) echo $e->getMessage();
            exit('DB Query Failed.');
        }
        return $count > 0;
    }
    
    
   /**
    * Create User Table
    *
    * This should only be ran ONCE!
    * This creates the user database table.  All of the table structure SQL is stored in
    * the file 'users.sql.php' to minimize clutter here.
    *
    * @param    void
    * @return   bool    true if success, false on fail
    * @access   public
    * @since    1.0
    */
    public function create_user_table()
    {
        $existing = array();
        
        if(!$this->check_table_exists('users'))
        {
            require_once 'users.sql.php'; // Require SQL file
           
            try {
                $this->exec($sql1);
            }
            catch(PDOException $e) {
                if(DEBUG) echo $e->getMessage();
                exit('Create Table Failed.');
            }
        }
        else
        {
            $existing[] = 'users';
        //    die('User table already exists!  Please remove the call to the method `create_user_table`.');
        }
        
        // Here to allow for multiple create tables testing
        if(count($existing) > 0) { 
            foreach($existing as $exists)
            {
                echo "<pre>Table `{$exists}` already exists!  Please remove the call to the method `create_user_table`.\n</pre>";
            }
            exit();
        }
        return true;
    }
}

$user = new userAuth;
//$user->create_user_table();
//$user->create_user('foo', 'bar');
var_dump($user->is_logged_in());
//$user->user_logout();
//var_dump($user->user_login('foo', 'bar'));

