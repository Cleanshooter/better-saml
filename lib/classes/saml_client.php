<?php
class SAML_Client
{

    private $saml;
    private $opt;
    private $secretsauce;
  
    function __construct()
    {

        $this->settings = new SAML_Settings();
    
        require_once( constant( 'SAMLAUTH_ROOT' ) . '/saml/lib/_autoload.php' );

        if( $this->settings->get_enabled() )
        {

            // Set up SAML auth instance
            $this->saml = new SimpleSAML_Auth_Simple( (string) get_current_blog_id() );

            // If the user is already authenticated via SAML, but not logged in yet
            // if( $this->saml->isAuthenticated() && !is_user_logged_in() )
            // {
            //     // Get their SAML attributes
            //    $attrs = $this->saml->getAttributes();
                // Simulate sign on with SAML username
            //    $this->simulate_signon( $attrs[ $this->settings->get_attribute( 'username' ) ][0] );
            //}

            // Is the current logged in user a SAML user
            
            // Add filters
            add_action( 'wp_authenticate', array( $this, 'authenticate' ) );
            add_action( 'wp_logout',       array( $this, 'logout' ) );
            add_action( 'login_form',      array( $this, 'modify_login_form' ) );
        }
    
        // Hash to generate password for SAML users.
        // This is never actually used by the user, but we need to know what it is, and it needs to be consistent
        
        // WARNING: If the WP AUTH_KEY is changed, all SAML users will be unable to login! In cases where this is
        // actually desired, such as an intrusion, you must delete SAML users or manually set their passwords.
        // it's messy, so be careful!

        $this->secretsauce = constant( 'AUTH_KEY' );
    }

  
    /**
    *  Authenticates the user using SAML
    *
    *  @return void
    */
    public function authenticate( $username, $password )
    {

        if( isset( $_GET['loggedout'] ) && $_GET['loggedout'] == 'true' )
        {
            header( 'Location: ' . get_option( 'siteurl' ) );
            exit();
        }

        elseif ( $this->settings->get_allow_sso_bypass() == true  && ( ( isset( $_GET['use_sso'] ) && $_GET['use_sso'] == 'false' ) || ( isset( $_POST['use_sso'] ) && $_POST['use_sso'] == 'false' ) ) )
        {
            // User wants native WP login, do nothing
        }

        else
        {
            // Attempt to load user by username
            if( $user = get_user_by( 'login', $username ) )
            {

                // If user is loaded, check if is a SAML user or if their in the allowed email domain list
                if( get_user_meta( $user->ID, '_saml_user', true ) == 1 || $this->check_email_domain( $user->data->user_email ) ) {

                    $redirect_url = ( array_key_exists( 'redirect_to', $_GET ) ) ? wp_login_url( $_GET['redirect_to'] ) : get_admin_url();

                    $this->saml->requireAuth( 
                        array( 'ReturnTo' => $redirect_url )
                    );

                    $attrs = $this->saml->getAttributes();

                    if( array_key_exists( $this->settings->get_attribute( 'username' ), $attrs ) )
                    {
                        $saml_username = $attrs[ $this->settings->get_attribute( 'username' ) ][0];
                    }
                    else
                    {
                        $saml_username = $username;
                    }

                    // Simulate SAML user sign on
                    $this->simulate_signon( $saml_username );
                }

                // ELSE: Do nothing if not
            }
            // If no user found, create them
            else
            {
                $this->new_user( $attrs );
            }
        }
    }


    /**
    * Check for valid SAML username attribute 
    * @return void
    */
    private function check_username_attribute( $fallback )
    {
        $allowed = $this->settings->get_allowed_email_domains();
        return strpos($allowed, $email_address);
    }


    /**
    * Check if the email address used to login is allowed to be passed to SAML 
    * @todo   Add wildcard checks and whatnot, its basically a string matcher now
    * @return void
    */
    private function check_email_domain($email_address)
    {
        $allowed = $this->settings->get_allowed_email_domains();
        return strpos($allowed, $email_address);
    }
  

    /**
    * Sends the user to the SAML Logout URL (using SLO if available) and then redirects to the site homepage
    *
    * @return void
    */
    public function logout()
    { 
        $this->saml->logout( get_option( 'siteurl' ) );
    }


    /**
    * Runs about halfway through the login form. If we're bypassing SSO, we need to add a field to the form
    *
    * @return void
    */
    public function modify_login_form() {

        if( array_key_exists('use_sso', $_GET) && $_GET['use_sso'] == 'false' && $this->settings->get_allow_sso_bypass() == true )
        {
            echo '<input type="hidden" name="use_sso" value="false">'."\n";
        }
    }
  

    /**
    * Creates a new user in the WordPress database using attributes from the IdP
    * 
    * @param array $attrs The array of attributes created by SimpleSAMLPHP
    * @return void
    */
    private function new_user($attrs)
    {
        if( array_key_exists($this->settings->get_attribute('username'),$attrs) )
        {
            $login = (array_key_exists($this->settings->get_attribute('username'),$attrs)) ? $attrs[$this->settings->get_attribute('username')][0] : 'NULL';
            $email = (array_key_exists($this->settings->get_attribute('email'),$attrs)) ? $attrs[$this->settings->get_attribute('email')][0] : '';
            $first_name = (array_key_exists($this->settings->get_attribute('firstname'),$attrs)) ? $attrs[$this->settings->get_attribute('firstname')][0] : '';
            $last_name = (array_key_exists($this->settings->get_attribute('lastname'),$attrs)) ? $attrs[$this->settings->get_attribute('lastname')][0] : '';
            $display_name = $first_name . ' ' . $last_name;
        }
        else
        {
            die('A username was not provided.');
        }

        $role = $this->update_role();

        if( $role !== false )
        {

            $user_opts = array(
                'user_login'   => $login ,
                'user_pass'    => $this->user_password( $login, $this->secretsauce ) ,
                'user_email'   => $email ,
                'first_name'   => $first_name ,
                'last_name'    => $last_name ,
                'display_name' => $display_name ,
                'role'         => $role,
            );

            // If we successfully created a user
            if( $user_id = wp_insert_user($user_opts) ) {

                // Identify them as a saml user
                add_user_meta( $user_id, '_saml_user', 1 );

                // Simulate the signon
                $this->simulate_signon( $login );
            }

            else {
                die( 'The user couldnt be created' );
            }
        }
        else
        {
            die('The website administrator has not given you permission to log in.');
        }
    }
  
    /**
    * Authenticates the user with WordPress using wp_signon()
    *
    * @param string $username The user to log in as.
    * @return void
    */
    private function simulate_signon( $username, $redirect_to = false )
    {
        remove_filter('wp_authenticate',array($this,'authenticate'));

        $this->update_role();

        $login = array(
          'user_login'    => $username,
          'user_password' => $this->user_password( $username, $this->secretsauce ),
          'remember'      => false
        );

        $use_ssl = ( defined('FORCE_SSL_ADMIN') && constant('FORCE_SSL_ADMIN') === true ) ? true : '';
        $result  = wp_signon( $login, $use_ssl );

        if(is_wp_error($result))
        {
            echo $result->get_error_message();
            exit();
        }
        else
        {
            // First check for a specific redirection URL
            if( $redirect_to )
            {
                wp_redirect( $redirect_to );
            }
            elseif( array_key_exists( 'redirect_to', $_GET ) )
            {
                wp_redirect( $_GET['redirect_to'] );
            }
            else
            {
                wp_redirect( get_admin_url() );
            }
            exit();
        }
    }

    /**
    * Updates a user's role if their current one doesn't match the attributes provided by the IdP
    *
    * @return string 
    */
    private function update_role()
    {
        $attrs = $this->saml->getAttributes();

        if( array_key_exists( $this->settings->get_attribute('groups'), $attrs ) )
        {
            if( in_array( $this->settings->get_group('admin'), $attrs[ $this->settings->get_attribute('groups') ] ) )
            {
                $role = 'administrator';
            }
            elseif( in_array( $this->settings->get_group('editor'), $attrs[ $this->settings->get_attribute('groups') ] ) )
            {
                $role = 'editor';
            }
            elseif( in_array( $this->settings->get_group('author'), $attrs[ $this->settings->get_attribute('groups') ] ) )
            {
                $role = 'author';
            }
            elseif( in_array( $this->settings->get_group('contributor'), $attrs[ $this->settings->get_attribute('groups') ] ) )
            {
                $role = 'contributor';
            }
            elseif( in_array( $this->settings->get_group('subscriber'), $attrs[ $this->settings->get_attribute('groups') ] ) )
            {
                $role = 'subscriber';
            }
            elseif( $this->settings->get_allow_unlisted_users() )
            {
                $role = 'subscriber';
            }
            else
            {
                $role = false;
            }
        }
        else
        {
            $role = false;
        }

        $user = get_user_by( 'login', $attrs[ $this->settings->get_attribute( 'username' ) ][0] );

        if($user)
        {
            $user->set_role($role);
        }

        return $role;
    }

    /**
    * Generates a SHA-256 HMAC hash using the username and secret key
    * 
    * @param string $value the user's username
    * @param string $key a secret key
    * @return string 
    */
    private function user_password($value,$key)
    {
        $hash = hash_hmac('sha256',$value,$key);
        return $hash;
    }

    public function show_password_fields($show_password_fields) {
        return false;
    }

    public function disable_function() {
        return !(bool) get_user_meta( get_current_user_id(), '_saml_user', true );
    }
  
} // End of Class SamlAuth