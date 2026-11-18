<?php
/**
 * Plugin Name: Secure WP User Enumeration
 * Plugin URI:  https://github.com/darkneiss/wordpress-tools
 * Description: Bloquea de forma segura la enumeración de usuarios (REST API, Autores, Sitemaps nativos/Yoast), ofusca errores de login y desactiva XML-RPC.
 * Version:     1.0.0
 * Author:      Tu Nombre
 * Text Domain: secure-user-enum
 * License:     GPL-2.0-or-later
 *
 * Prevención de enumeración de usuarios.
 * Basado en las recomendaciones de seguridad de la comunidad WordPress.
 * Referencia: https://inspectwp.com/en/knowledge-base/how-to-prevent-user-enumeration-wordpress
 */

namespace SecureUserEnum\Security;

// Prevención de acceso directo.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Clase principal para proteger la enumeración de usuarios y endpoints de ataque.
 */
class UserEnumerationBlocker {

    /**
     * Instancia única de la clase (Patrón Singleton).
     *
     * @var UserEnumerationBlocker|null
     */
    private static ?UserEnumerationBlocker $instance = null;

    /**
     * Obtiene la instancia de la clase.
     *
     * @return UserEnumerationBlocker
     */
    public static function get_instance(): UserEnumerationBlocker {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Constructor. Registra los hooks de seguridad.
     */
    private function __construct() {
        // Hooks Nativos de WordPress
        add_filter( 'rest_endpoints', [ $this, 'disable_rest_user_endpoints' ] );
        add_filter( 'login_errors', [ $this, 'obfuscate_login_errors' ] );
        add_action( 'template_redirect', [ $this, 'block_author_archives' ], 1 );
        add_filter( 'wp_sitemaps_add_provider', [ $this, 'disable_users_sitemap' ], 10, 2 );
        add_filter( 'xmlrpc_enabled', [ $this, 'disable_xmlrpc' ] );
        
        // Hooks para Plugins de SEO (Yoast)
        add_filter( 'wpseo_sitemap_author', [ $this, 'disable_yoast_author_sitemap' ] );
    }

    /**
     * 1. Elimina los endpoints de usuarios de la REST API para visitantes.
     */
    public function disable_rest_user_endpoints( array $endpoints ): array {
        if ( ! is_user_logged_in() ) {
            if ( isset( $endpoints['/wp/v2/users'] ) ) {
                unset( $endpoints['/wp/v2/users'] );
            }
            if ( isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) ) {
                unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
            }
        }
        return $endpoints;
    }

    /**
     * 2. Enmascara los errores de login para evitar adivinación de usuarios.
     */
    public function obfuscate_login_errors( string $error ): string {
        return sprintf(
            '<strong>%s</strong> %s',
            esc_html__( 'Error:', 'secure-user-enum' ),
            esc_html__( 'El usuario o la contraseña son incorrectos.', 'secure-user-enum' )
        );
    }

    /**
     * 3. Bloquea las peticiones a las páginas de archivo de autor (/?author=1).
     */
    public function block_author_archives(): void {
        if ( isset( $_GET['author'] ) || is_author() ) {
            global $wp_query;

            remove_action( 'template_redirect', 'redirect_canonical' );

            $wp_query->set_404();
            status_header( 404 );
            nocache_headers();
        }
    }

    /**
     * 4. Elimina los usuarios de los sitemaps nativos de WordPress.
     */
    public function disable_users_sitemap( $provider, string $name ) {
        if ( 'users' === $name ) {
            return false;
        }
        return $provider;
    }

    /**
     * 5. Elimina el sitemap de autores generado por Yoast SEO.
     */
    public function disable_yoast_author_sitemap(): bool {
        return false;
    }

    /**
     * 6. Desactiva el acceso a xmlrpc.php para frenar ataques de fuerza bruta y DDoS.
     */
    public function disable_xmlrpc(): bool {
        return false;
    }
}

// Inicializa la clase.
UserEnumerationBlocker::get_instance();
