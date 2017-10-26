<?php

/**
 * ConnectLDAP class
 *
 * @author Romain Odeval
 * Manage LDAP connections
 */
class ConnectLDAP {

    private $baseDN;
    private $ldapServer;
    private $ldapServerPort = 389;
    private $mdp;
    private $rdn;
    private $connect;
    private $protocol;
    private $error; //array(num erreur,texte erreur)
    private $secureMode;

    /**
     * Constructor
     * The first parameter is useful when you have a strong LDAP system. For example :
     *  - 0 : create a connection for a master OpenLDAP, for writing only
     *  - 1 : create a connection for a replicating slave OpenLDAP, for reading only
     *  - 2 : create a connection for a replicating slave OpenLDAP, for "emergency reading" only
     *  - 3 : create a connection for an Active Directory
     * by default, connection 1 is used.
     * The second parameter is a switch for a classic connection or a secured connection
     *
     * @param numeric $choix_ldap 
     * @param boolean $choix_ssl
     */
    public function __construct($choix_ldap = 1, $choix_ssl = FALSE) {

        // Gestion du protocole de connexion LDAP à utiliser (si le port est un port "classique")
        if ($choix_ssl == TRUE) {
            $this->secureMode = true;
            $this->protocol = "ldaps://";
        } else {
            $this->secureMode = false;
            $this->protocol = "ldap://";
        }

        switch ($choix_ldap) {
            case 0:
                // Example with a non-classic LDAP port
                $this->baseDN = "dc=example,dc=fr";
                $this->ldapServer = "localhost";
                $this->ldapServerPort = 666;
                $this->mdp = "password1";
                $this->rdn = "uid=root,ou=System,ou=people," . $this->baseDN;
                break;
            case 1:
                // Example with IP address
                $this->baseDN = "dc=example,dc=fr";
                $this->ldapServer = "172.21.0.7";
                $this->mdp = "password2";
                $this->rdn = "uid=find,ou=System,ou=people," . $this->baseDN;
                break;
            case 2:
                // Another IP address example
                $this->baseDN = "dc=example,dc=fr";
                $this->ldapServer = "172.21.0.130";
                $this->mdp = "password3";
                $this->rdn = "uid=find,ou=System,ou=people," . $this->baseDN;
                break;
            case 3:
                // Active directory example
                $this->baseDN = "DC=LABS,DC=local";
                $this->ldapServer = "172.21.0.112";
                $this->ldapServerPort = 636;
                $this->mdp = "password4";
                $this->rdn = "CN=applicatifs app. applicatifs,CN=Users,DC=LABS,DC=local";
                break;
        }
    }

    /**
     * connexion à l'annuaire ldap
     * @return boolean vrai si la connexion est valide et authentifiée
     */
    public function connect() {
        $this->connect = ldap_connect($this->protocol . $this->ldapServer . ":" . $this->ldapServerPort, $this->ldapServerPort);
        if ($this->connect) {
            if ($this->addLdapOption(LDAP_OPT_PROTOCOL_VERSION, 3)) {
                if (ldap_bind($this->connect, $this->rdn, $this->mdp)) {
                    return true;
                }
                $this->setError();
                $this->error['text'] .= " " . $this->protocol . $this->ldapServer . ":" . $this->ldapServerPort;
                return false;
            } else {
                $this->setError();
                return false;
            }
        } else {
            $this->setError();
            return false;
        }
    }

    public function addLdapOption($option, $newVal) {
        return ldap_set_option($this->connect, $option, $newVal);
    }

    /**
     * retourne le lien de connexion au LDAP
     */
    public function getConnect() {
        return $this->connect;
    }

    /**
     * retourne le RDN de connexion au LDAP
     */
    public function getRDN() {
        return $this->rdn;
    }

    /**
     * retourne le baseDN de connexion au LDAP
     */
    public function getBaseDN() {
        return $this->baseDN;
    }

    /**
     * Shutdown LDAP connection
     */
    public function close() {
        ldap_unbind($this->connect);
    }

    /**
     * gère l'erreur de la dernière commande ldap passée
     */
    private function setError() {
        $this->error = array();
        $this->error["number"] = ldap_errno($this->connect);
        $this->error["text"] = ldap_error($this->connect);
    }

    /**
     * récupère la dernière erreur Ldap générée, number= numéro d'erreur, text = texte de l'erreur
     * @return array
     */
    public function getError() {
        return $this->error;
    }

}

?>
