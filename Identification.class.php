<?php

/**
 * Description of Identification
 *
 * @author Romain Odeval
 * vérification des droits utilisateur sur un applicatif dans mysql ou ldap
 */
class Identification {

    public static function hasRightMysql($uid) {
        if (!is_null($uid) && !empty($uid)) {
            $group = new Group();
            $result = $group->getGroup($uid);
            if (!$result) {
                return false;
            } else {
                if ($result == GROUP::ADMIN_GROUP || $result == GROUP::GOD_GROUP) {
                    return true;
                } else {
                    $_SESSION['error'] = "Vous n'êtes pas autoris&eacute;";
                    return false;
                }
            }
        } else {
            return false;
        }
    }

    /**
     * fonction permettant de vérifier si une personne a des droits d'accès enregistrés dans le LDAP.
     * Cas 1 : on vérifie juste que le compte existe dans l'annuaire LDAP (quand $nom_applicatif est nul).
     * Cas 2 : on vérifie si un compte a des droits d'accès pour un applicatif donné.
     * Cas 2bis : on vérifie si un compte a des droits d'administration pour un applicatif donné.
     *
     * @param string $uid
     * @param string $nom_applicatif optional
     * @param int $admin optional
     */
    public static function hasRightLdap($uid, $nom_applicatif = null, $admin = 0) {
        $tableau_droits = array();
        $ldap_verif_droit = new ConnexionLDAP(1);
        if ($ldap_verif_droit->connect()) {
            $requete_ldap = new Ldap($ldap_verif_droit->getConnect(), $ldap_verif_droit->getBaseDN());
            $tab_ldap_utilisateur = $requete_ldap->searchUid($uid);
            if (is_null($nom_applicatif)) {
                // Cas 1 : Existance du compte dans le LDAP
                // on cherche les informations de la personne
                if (isset($tab_ldap_utilisateur['cn']) && $tab_ldap_utilisateur['cn'] != '') {
                    $ldap_verif_droit->close();
                    return true;
                } else {
                    $_SESSION['error_right_ldap'] = "Ce compte n'existe pas dans l'annuaire LDAP";
                    return false;
                }
            } else {
                // Cas 2 : Droit de connexion lié à un applicatif
                // Sélection du type de recherche : droits d'accès (==0) ou droits d'administration (==1)
                // REM : On n'utilise pas de booléens dans le cas où on voudrait rajouter un jour d'autres types de droit (gestion, ...)
                //@TODO gérer proprement le nom des droits dans le reste de la fonction
                $adresse_cn_ldap = 'cn=' . $tab_ldap_utilisateur['cn'] . ',ou=Utilisateurs,' . $ldap_verif_droit->getBaseDN();
                $validation = 0;
                $nom_droit = NULL;

                if ($admin == 1) {
                    $nom_droit = "admin";
                }
                $tableau_droits = $requete_ldap->searchAutorisationsApplicatif($nom_applicatif, $nom_droit);

                if ($tableau_droits['count'] > 0) {
                    foreach ($tableau_droits[0]['member'] as $ligne) {
                        if ($ligne == $adresse_cn_ldap) {
                            $validation++;
                        }
                    }
                } else {
                    $validation = 0;
                }

                if ($validation > 0) {
                    $_SESSION['autorisation_gestion_' . $nom_applicatif] = true;
                    $_SESSION['autorisation_admin_' . $nom_applicatif] = false;
                    if ($admin == 1) {
                        $_SESSION['autorisation_admin_' . $nom_applicatif] = true;
                    }
                    $ldap_verif_droit->close();
                    return true;
                } else {
                    $_SESSION['autorisation_gestion_' . $nom_applicatif] = false;
                    $_SESSION['autorisation_admin_' . $nom_applicatif] = false;
                    $ldap_verif_droit->close();
                    return false;
                }
            }
        } else {
            $_SESSION['error_right_ldap'] = "Connexion à l'annuaire LDAP impossible";
            return false;
        }
    }

    /**
     * détruit les informations de session
     * et déloggue
     */
    public static function destroyAuth() {
        $_SESSION['autorisation'] = FALSE;
        $_SESSION['autorisation_gestion'] = FALSE;
        $_SESSION['autorisation_admin'] = FALSE;
        unset($_SESSION['uid']);
        unset($_SESSION['id_individu']);
        unset($_SESSION['cn']);
        unset($_SESSION['nom']);
        unset($_SESSION['prenom']);
        unset($_SESSION['email']);
        unset($_SESSION['geoloc']);
        unset($_SESSION['employeeNumber']);
        unset($_SESSION['id_type_individu']); // Nouveau système
        session_unset();
        setcookie("userUid", "", time() - 3600);
        setcookie("userReference", "", time() - 3600);
        unset($_COOKIE["userUid"]);
        unset($_COOKIE["userReference"]);
        session_destroy();
        session_start();
    }

}

?>
