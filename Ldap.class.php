<?php

/**
 * Description of Ldap
 *
 * @author Romain Odeval
 * Manage LDAP requests and user authentification (with Identification.class.php)
 */
class Ldap {

    const RDN_USERS = "ou=people";
    const RDN_APPS = "ou=applications";
    const RDN_GROUPES = "ou=groups";

    private $baseDN;
    private $connect;
    private $resultset;
    private $mdp;
    private $apMdp;

    /**
     * mode de débogage
     * @var boolean
     */
    private $debugLdapMode = false;

    /**
     * texte de débogage
     * @var string
     */
    private $debugLdapText;

    /**
     * Constructeur
     */
    public function __construct($lienVersLDAP, $DNconnexion) {
        if (!is_null($lienVersLDAP) && !empty($lienVersLDAP) && !is_null($DNconnexion) && !empty($DNconnexion)) {
            $this->connect = $lienVersLDAP;
            $this->baseDN = $DNconnexion;
        }
    }

    public function setDebugLDAP($boolean) {
        if (is_bool($boolean)) {
            $this->debugLdapMode = $boolean;
        }
    }

    /**
     * Retourne le texte de débogage
     * @return string
     */
    public function getDebugLDAPText() {
        return $this->debugLdapText;
    }

    public function getApacheMdp() {
        return $this->apMdp;
    }

    public function getMdp() {
        return $this->mdp;
    }

    public function getBaseDN() {
        return $this->baseDN;
    }

    /**
     * recherche par nom
     * @param string $nom
     * @return arraylist
     */
    public function searchName($nom) {

        $filter = "(&(objectClass=posixAccount)(cn=" . $nom . "*))";
        $attribs = array("uid", "cn", "mailLocalAddress", "roomNumber");
        $this->resultset = ldap_search($this->connect, $this->baseDN, $filter, $attribs);
        return ldap_get_entries($this->connect, $this->resultset);
    }

    /**
     * recherche des autorisations d'accès pour un applicatif donné et un droit donné
     * @param string $nom_applicatif optionnel
     * @return arraylist
     */
    public function searchAutorisationsApplicatif($nom_applicatif, $nom_droit = '') {

        $filter = '';

        if (isset($nom_droit) && $nom_droit != '' && $nom_droit != NULL) {
            $filter = "ou=" . $nom_droit . "";
        } else {
            $filter = "ou=" . $nom_applicatif . "";
        }
        $attribs = array("member");
        if (isset($nom_droit) && $nom_droit != '' && $nom_droit != NULL) {
            $this->resultset = ldap_search($this->connect, "ou=" . $nom_applicatif . ',ou=Applications,' . $this->baseDN, $filter, $attribs);
        } else {
            $this->resultset = ldap_search($this->connect, 'ou=Applications,' . $this->baseDN, $filter, $attribs);
        }
        return ldap_get_entries($this->connect, $this->resultset);
    }

    /**
     * recherche des autorisations d'administration pour un applicatif
     * @param string $nom_applicatif
     * @return arraylist
     */
    // @TODO fonction gardée pour rétro-compatabilité. A supprimer quand les outils auront été mis à jour
    public function searchAutorisationsAdminApplicatif($nom_applicatif) {

        $filter = "ou=admin";
        $attribs = array("member");
        $this->resultset = ldap_search($this->connect, 'ou=' . $nom_applicatif . ',ou=Applications,' . $this->baseDN, $filter, $attribs);
        return ldap_get_entries($this->connect, $this->resultset);
    }

    /**
     * recherche des infos d'un individu à partir d'un uid
     *
     * @param string $uid
     * @return arraylist OR 0 OR false
     */
    public function searchUid($uid) {
        $filter = "(&(objectClass=posixAccount)(uid=" . $uid . "))";
        $attribs = array("uid", "cn", "mailLocalAddress", "roomNumber");
        $this->resultset = ldap_search($this->connect, $this->baseDN, $filter, $attribs);
        $recherche = ldap_get_entries($this->connect, $this->resultset);

        if ($recherche['count'] == 0) { // Premier cas : la recherche a fonctionnée mais elle ne renvoie aucun résultat
            $resultat = 0;
        } else {    // Deuxième cas : la recherche renvoie au moins un résultat correcte
            $resultat = $this->format($recherche[0]);
        }

        return $resultat;
    }

    /**
     * recherche des infos d'un individu à partir d'un cn
     *
     * @param string $cn
     * @return arraylist OR 0 OR false
     */
    public function searchInfosIndividu($cn) {
        $filter = "cn=" . $cn . "";
        $attribs = array("cn", "sn", "givenName", "employeeNumber", "businessCategory", "employeeType", "mailLocalAddress", "roomNumber", "userPassword");
        $this->resultset = ldap_search($this->connect, 'ou=Utilisateurs,' . $this->baseDN, $filter, $attribs);
        $recherche = ldap_get_entries($this->connect, $this->resultset);

        if ($recherche['count'] == 0) { // Premier cas : la recherche a fonctionnée mais elle ne renvoie aucun résultat
            $resultat = 0;
        } else {    // Deuxième cas : la recherche renvoie au moins un résultat correcte
            $resultat = $this->format($recherche[0]);
        }

        return $resultat;
    }

    /**
     * recherche des infos (attributs) dans l'annuaire LDAP, à partir d'une arborescence complète (moins le baseDN)
     *
     * @param string $dn
     * @param string $filtre
     * @param array $attributs
     * 
     * @return arraylist OR 0 OR false
     */
    public function searchLDAP($dn, $filtre, $attributs) {
        $this->resultset = ldap_search($this->connect, $dn . ',' . $this->baseDN, $filtre, $attributs);
        $recherche = ldap_get_entries($this->connect, $this->resultset);

        if ($recherche['count'] == 0) { // Premier cas : la recherche a fonctionnée mais elle ne renvoie aucun résultat
            $resultat = 0;
        } else {    // Deuxième cas : la recherche renvoie au moins un résultat correct
            $resultat = $recherche;
        }
        $this->debugLDAP($this->connect, "recherche LDAP");
        return $resultat;
    }

    /**
     * Génération d'un CN pour un annuaire LDAP
     * avec vérification/gestion des doublons
     *
     * @param string $nom
     * @param string $prenom
     */
    public function genererCN($nom, $prenom) {
        if (!isset($nom) || !isset($prenom) || $nom != '' || $prenom != '') {
            $cn = $nom . " " . $prenom;
            $i = 1;
            while ($this->searchInfosIndividu($cn) != 0) {

                $i++;
                $cn = $cn . " (" . $i . ")";
            }
            return $cn;
        } else {
            $_SESSION['error'] = "Le prénom ou le nom sont manquants. Arrêt de la génération du CN.";
            return false;
        }
    }

    public function modifyLDAP($rdn, $donnees) {
        if (!is_null($rdn) && !empty($rdn) && !is_null($donnees) && is_array($donnees) && count($donnees) > 0) {
            try {
                if (ldap_modify($this->connect, $rdn, $donnees)) {
                    return true;
                } else {
                    $this->debugLDAP($this->connect, "modify rdn=" . $rdn);
                    return false;
                }
            } catch (Exception $ex) {
                $this->debugLDAP($this->connect, "modify rdn=" . $rdn);
                return false;
            }
        } else {
            return false;
        }
    }

    /**
     *  Insertion de nouvelles données dans l'annuaire LDAP
     *  $ou correspond aux différentes branches avec les balises "ou=" et "cn=" (sans le baseDN)
     *  $option permet de choisir entre l'insertion d'une nouvelle entrée (avec ces attributs) ou l'insertion de nouveaux attributs dans une entrée existante
     *
     * @param string $ou arborescence
     * @param array $donnees données
     * @param string $option
     */
    public function insertLDAP($ou, $donnees, $option = 'entree') {

        if (isset($donnees) && ($donnees != '') && isset($ou) && ($ou != '')) {
            // Deuxième étape : insertion dans LDAP
            if ($option == 'entree') {
                $this->resultset = ldap_add($this->connect, $ou . "," . $this->baseDN, $donnees); // Ajout d'une nouvelle entrée et ces attributs
            } elseif ($option == 'attribut') {
                $this->resultset = ldap_mod_add($this->connect, $ou . "," . $this->baseDN, $donnees); // Ajout d'attributs dans une entrée existante
            }
            $this->debugLDAP($this->connect, "insert " . $option . " LDAP");
            return $this->resultset;
        } else {
            $_SESSION['error'] = "Aucune information à insérer ou arborescence vide. Arrêt de l'insertion LDAP.";
            return false;
        }
    }

    /**
     *  Suppression de données dans le LDAP
     *  $ou correspond aux différentes branches avec les balises "ou=" et "cn=" (sans le baseDN)
     *  Si $entree est vide, on supprime toute l'entrée CN ou OU
     *
     * @param string $ou arborescence
     * @param array $entree données
     */
    public function deleteLDAP($ou, $entree = '') {

        if (isset($ou) && ($ou != '')) {
            // Deuxième étape : suppression dans LDAP
            if (isset($entree) && ($entree != '')) {
                $this->resultset = ldap_mod_del($this->connect, $ou . "," . $this->baseDN, $entree);
            } else {
                $this->resultset = ldap_delete($this->connect, $ou . "," . $this->baseDN);
            }
            $this->debugLDAP($this->connect, "delete LDAP");
            return $this->resultset;
        } else {
            $_SESSION['error'] = "Aucune information à insérer ou arborescence vide. Arrêt de l'insertion LDAP.";
            return false;
        }
    }

    /**
     * authentification d'une personne
     * @param string $uid
     * @param string $userPassword
     * @param string $nom_applicatif optional
     * @param bool $admin optional
     * @return boolean
     */
    public function authenticate($uid, $userPassword, $nom_applicatif = null, $admin = 0, $cookieByPass = false) {

        // on vérifie si l'utilisateur a bien rempli les champs d'identification
        if (!$cookieByPass && (!isset($uid) || !isset($userPassword) || empty($uid) || empty($userPassword))) {
            $_SESSION['error'] = "Veuillez remplir tous les champs";
            return false; // uid et password sont obligatoires
        }

        // On vérifie si la personne a déjà été authentifié, sinon on lance la procédure d'authentification
        if (isset($_SESSION['autorisation']) && $_SESSION['autorisation'] == true) {
            return true;
        } else {
            // On vérifie les informations d'identification
            if (Identification::hasRightLdap($uid, $nom_applicatif, $admin)) {
                if (!is_null($this->connect)) {
                    $cn_individu = $this->searchUid($uid);
                    $infos_individu = $this->searchInfosIndividu($cn_individu['cn']);
                } else {
                    $_SESSION['autorisation'] = false;
                    $_SESSION['error'] = "Problème de connexion au LDAP";
                    return false;
                }
                if ($infos_individu) { // si la personne est connue, on charge ses informations
                    $cn = $infos_individu["cn"];
                    $mail = $infos_individu["email"];
                    $allMail = $infos_individu["allMail"];
                    $room = $infos_individu["geoloc"];
                    $prenom = $infos_individu["prenom"];
                    $nom = $infos_individu["nom"];
                    $id_ind = $infos_individu["employeeNumber"];
                    $type_ind = $infos_individu["employeeType"]; // Ancien système, à supprimer dès que tous les anciens outils (antérieurs à 2011) ont été modifiés ou supprimés
                    $id_type_ind = $infos_individu["businessCategory"]; // Nouveau système
                    $pass = $infos_individu["mdp"];

                    // condition cookieByPass disneyLand security
                    // On chiffre le MdP écrit par l'utilisateur via l'interface, afin de le comparer après au MdP chiffré du LDAP
                    $this->encrypt($userPassword, $cookieByPass);

                    if (strcasecmp($this->mdp, $pass) == 0) { // Comparaison du mot de passe dans LDAP avec celui renseigné
                        if ($nom && $prenom && $id_ind && $type_ind) {

                            $_SESSION['uid'] = $uid;
                            $_SESSION['cn'] = $cn;
                            $_SESSION['id_individu'] = $id_ind; // Nouvelle appelation, plus logique car n'inclus pas que les employés
                            $_SESSION['employeeNumber'] = $id_ind; // Ancienne appelation, pour les anciens outils. A NE PAS UTILISER POUR LES FUTURS OUTILS, CREES APRES SEPTEMBRE 2011
                            $_SESSION['employeeType'] = $type_ind; // Ancien système, à supprimer dès que tous les anciens outils (antérieurs à 2011) ont été modifiés ou supprimés
                            $_SESSION['id_type_individu'] = $id_type_ind; // Nouveau système
                            $_SESSION['nom'] = $nom;
                            $_SESSION['prenom'] = $prenom;
                            $_SESSION['email'] = $mail;
                            $_SESSION['allMail'] = $allMail;
                            $_SESSION['geoloc'] = $room;

                            /*
                             * Il existe 3 types d'autorisation :
                             *  $_SESSION['autorisation'] => correspond à l'autorisation d'accéder à l'outil car l'utilisateur est présent dans le LDAP avec bon couple login/mdp. Délivrée par cette fonction, "authenticate"
                             *  $_SESSION['autorisation_gestion'] => correspond à l'autorisation de gérer des choses dans un outil. Délivrée par la fonction "HasRightLDAP" de la classe "Identification".
                             *  $_SESSION['autorisation_admin'] =>  correspond à l'autorisation d'e gérer'administrer un outil. Délivrée par la fonction "HasRightLDAP" de la classe "Identification".
                             *
                             * Sans la première autorisation, qui correspond uniquement à un bon renseignement login/mdp, les deux autres sont inutiles.
                             * NB : si $_SESSION['autorisation_admin'] est égal à TRUE, alors $_SESSION['autorisation_gestion'] est aussi égal à TRUE
                             */

                            $_SESSION['autorisation'] = true;
                            return true;
                        } else {
                            $_SESSION['autorisation'] = false;
                            $_SESSION['error'] = "Certaines informations essentielles ne sont pas présentes dans l'annuaire LDAP";
                            return false;
                        }
                    } else {
                        $_SESSION['autorisation'] = false;
                        $_SESSION['error'] = "Votre mot de passe de connexion est incorrect";
                        return false;
                    }
                } else {
                    $_SESSION['autorisation'] = false;
                    $_SESSION['error'] = "La recherche de votre identifiant dans le LDAP n'a pas abouti à un résultat";
                    return false;
                }
            } else {
                $_SESSION['autorisation'] = false;
                $_SESSION['error'] = "Vous n'avez pas les droits requis pour accéder à cet applicatif";
                return false;
            }
        }
    }

    /**
     * formate une entrée de type utilisateur pour les recherches LDAP
     * NB : le retour peut etre directement utilisé pour faire une insertion dans MySQL
     * 
     * @param ldapArray $recherche une entrée de recherche ldap
     * @return array un tableau contenant les informations formatées d'une entrée
     */
    public function format($recherche) {

        if (isset($recherche["uid"][0])) {
            $uid = $recherche["uid"][0];
        } else {
            $uid = "";
        }

        // ATTENTION ! A ce niveau, le mot de passe est toujours chiffré !
        if (isset($recherche["userpassword"][0])) {
            $userPassword = $recherche["userpassword"][0];
        } else {
            $userPassword = "";
        }

        if (isset($recherche["sn"][0])) {
            $sn = $recherche["sn"][0];
        } else {
            $sn = "";
        }

        if (isset($recherche["cn"][0])) {
            $cn = $recherche["cn"][0];
        } else {
            $cn = "";
        }

        if (isset($recherche["givenname"][0])) {
            $givenName = $recherche["givenname"][0];
        } else {
            $givenName = "";
        }

        if (isset($recherche["employeetype"][0])) {
            $employeeType = $recherche["employeetype"][0];
        } else {
            $employeeType = "";
        }

        if (isset($recherche["businesscategory"][0])) {
            $idTypeIndividu = $recherche["businesscategory"][0];
        } else {
            $idTypeIndividu = "";
        }

        if (isset($recherche["maillocaladdress"][0])) {
            $mail = $recherche["maillocaladdress"][0];
            $allMail = array();
            $allMail[] = $recherche["maillocaladdress"];
        } else {
            $mail = "";
            $allMail = array();
        }

        if (isset($recherche["employeenumber"][0])) {
            $employeeNumber = $recherche["employeenumber"][0];
        } else {
            $employeeNumber = "";
        }

        if (isset($recherche["roomnumber"][0])) {
            $room = $recherche["roomnumber"][0];
        } else {
            $room = "";
        }

        // Mise en forme dans un tableau compréhensif (en français)
        $donnees = array();
        $donnees["uid"] = $uid;
        $donnees["mdp"] = $userPassword;
        $donnees["cn"] = $cn;
        $donnees["email"] = $mail;
        $donnees["allMail"] = $allMail;
        $donnees["geoloc"] = $room;
        $donnees["prenom"] = $givenName;
        $donnees["nom"] = $sn;
        $donnees["employeeNumber"] = $employeeNumber;
        $donnees["employeeType"] = $employeeType;
        $donnees["businessCategory"] = $idTypeIndividu;

        return $donnees;
    }

    /**
     * permet de déboguer facilement les requetes LDAP en voyant le type d'erreur renvoyé par l'annuaire
     * @param string $query
     * @param string $type
     */
    private function debugLDAP($lienLDAP, $type) {
        $num_erreur_ldap = "";
        $texte_erreur_ldap = "";
        if ($this->debugLdapMode) {
            $num_erreur_ldap = ldap_errno($lienLDAP);
            $texte_erreur_ldap = ldap_err2str($num_erreur_ldap);
            $this->debugLdapText = "<br />requete " . $type . "<br />";
            if (is_numeric($num_erreur_ldap)) {
                $this->debugLdapText .= " - erreur n°" . $num_erreur_ldap . " : " . $texte_erreur_ldap;
            }
            $this->debugLdapText .="<br />";
            echo $this->debugLdapText;
        }
    }

    /**
     * Fonction chiffrant le mot de passe utilisateur en MD5, sur une base 64
     *
     * @param string $mdp un mot de passe à chiffrer
     * @return string
     */
    public function encrypt($mdp, $withNoHash = false) {
        if (!$withNoHash) {
            $this->apMdp = '{MD5}' . base64_encode(md5($mdp, TRUE));
            $this->mdp = '{MD5}' . base64_encode(md5($mdp, TRUE));
        } else {
            $this->mdp = '{MD5}' . $mdp;
        }
    }

    /**
     * crypte un mot de passe en unicode password pour l'active directory
     * @param string $mdp
     * @return string
     */
    public function encryptAD($mdp) {
        $password = "\"" . $mdp . "\"";
        $passinit = "";
        for ($i = 0; $i < strlen($password); $i++) {
            $passinit .= "{$password{$i}}\000";
        }
        return $passinit;
    }

    /**
     * Fonction retournant un hash NTLM utilisable par Samba, pour une suite de caractères donnée.
     *
     * @param string $Input
     * @return string
     */
    public function NTLMHash($Input) {
        $Input = iconv('UTF-8', 'UTF-16LE', $Input);
        $MD4Hash = hash('md4', $Input);
        $NTLMHash = strtoupper($MD4Hash);
        return($NTLMHash);
    }

    /**
     * Fonction retournant un hash LM utilisable par Samba, pour une suite de caractères donnée.
     *
     * @param string $Input
     * @return string
     */
    public function LMhash($string) {
        $string = strtoupper(substr($string, 0, 14));

        $p1 = $this->LMhash_DESencrypt(substr($string, 0, 6));
        $p2 = $this->LMhash_DESencrypt(substr($string, 7, 14));

        return strtoupper($p1 . $p2);
    }

    /**
     * Fonction "hashant" une partie du futur hash LM pour Samba
     *
     * @param string $Input
     * @return string
     */
    private function LMhash_DESencrypt($string) {
        $key = array();
        $tmp = array();
        $len = strlen($string);

        for ($i = 0; $i < 7; ++$i)
            $tmp[] = $i < $len ? ord($string[$i]) : 0;

        $key[] = $tmp[0] & 254;
        $key[] = ($tmp[0] << 7) | ($tmp[1] >> 1);
        $key[] = ($tmp[1] << 6) | ($tmp[2] >> 2);
        $key[] = ($tmp[2] << 5) | ($tmp[3] >> 3);
        $key[] = ($tmp[3] << 4) | ($tmp[4] >> 4);
        $key[] = ($tmp[4] << 3) | ($tmp[5] >> 5);
        $key[] = ($tmp[5] << 2) | ($tmp[6] >> 6);
        $key[] = $tmp[6] << 1;

        $is = mcrypt_get_iv_size(MCRYPT_DES, MCRYPT_MODE_ECB);
        $iv = mcrypt_create_iv($is, MCRYPT_RAND);
        $key0 = "";

        foreach ($key as $k)
            $key0 .= chr($k);
        $crypt = mcrypt_encrypt(MCRYPT_DES, $key0, "KGS!@#$%", MCRYPT_MODE_ECB, $iv);

        return bin2hex($crypt);
    }

}

?>
