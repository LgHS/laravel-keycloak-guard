<?php

namespace Lghs\KeycloakGuard\Auth\Guard;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Lghs\KeycloakGuard\Auth\AccessToken;
use Lghs\KeycloakGuard\Exceptions\CallbackException;
use Lghs\KeycloakGuard\Models\User;
use Lghs\KeycloakGuard\Facades\Keycloak;
use Illuminate\Contracts\Auth\UserProvider;

class KeycloakGuard implements Guard
{
    /**
     * @var null|Authenticatable|User
     */
    protected $user;

    /**
     * Constructor.
     *
     * @param Request $request
     */
    public function __construct(UserProvider $provider, Request $request)
    {
        $this->provider = $provider;
        $this->request = $request;
    }

    /**
     * Determine if the current user is authenticated.
     *
     * @return bool
     */
    public function check()
    {
        return (bool) $this->user();
    }

    /**
     * Determine if the current user is a guest.
     *
     * @return bool
     */
    public function guest()
    {
        return ! $this->check();
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        if (empty($this->user)) {
            $this->authenticate();
        }

        return $this->user;
    }

    /**
     * Set the current user.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function setUser(?Authenticatable $user)
    {
        $this->user = $user;
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return int|string|null
     */
    public function id()
    {
        $user = $this->user();
        return $user->id ?? null;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     *
     * @throws BadMethodCallException
     *
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        if (empty($credentials['access_token']) || empty($credentials['id_token'])) {
            return false;
        }

        /**
         * Store the section
         */
        $credentials['refresh_token'] = $credentials['refresh_token'] ?? '';
        Keycloak::saveToken($credentials);

        return $this->authenticate();
    }

    /**
     * Try to authenticate the user
     *
     * @return boolean
     * @throws CallbackException
     */
    public function authenticate()
    {
        // Get Credentials
        $credentials = Keycloak::retrieveToken();
        if (empty($credentials)) {
            return false;
        }

        $user = Keycloak::getUserProfile($credentials);
        if (empty($user)) {
            Keycloak::forgetToken();

            if (Config::get('app.debug', false)) {
                throw new CallbackException('User cannot be authenticated.');
            }

            return false;
        }

        // Provide User
        $user = $this->provider->retrieveByCredentials($user);
        $this->setUser($user);

        return true;
    }

    public function roles($prefix = false) {
        return [...$this->realm_roles(), ...$this->resource_roles($prefix, true)];
    }
    /**
     * Check user is authenticated and return his realm roles
     *
     * @param string $resource Default is empty: point to client_id
     *
     * @return array
     */
    public function realm_roles()
    {

        if (! $this->check()) {
            return false;
        }

        $token = Keycloak::retrieveToken();

        if (empty($token) || empty($token['access_token'])) {
            return false;
        }

        $token = new AccessToken($token);
        $token = $token->parseAccessToken();

        $realmRoles = $token['realm_access'] ?? [];
        $realmRoles = $realmRoles['roles'] ?? [];

        return $realmRoles;
    }

    /**
     * Check user is authenticated and return his resource roles
     *
     * @param string $resource Default is empty: point to client_id
     *
     * @return array
     */
    public function resource_roles($prefix = false, $all = false)
    {
        $resource = Config::get('keycloak.client_id');

        if (! $this->check()) {
            return false;
        }

        $token = Keycloak::retrieveToken();

        if (empty($token) || empty($token['access_token'])) {
            return false;
        }

        $token = new AccessToken($token);
        $token = $token->parseAccessToken();

        $resourceRoles = $token['resource_access'] ?? [];
        if($all) {
            $roles = [];
            foreach($resourceRoles as $resource => $resources) {
                if(isset($resources['roles'])) {
                    foreach($resources['roles'] as $resourceRole) {
                        $roles[] = $resource.'/'.$resourceRole;
                    }
                }
            }
            $resourceRoles = $roles;
        } else {
            $resourceRoles = $resourceRoles[ $resource ] ?? [];
            $resourceRoles = $resourceRoles['roles'] ?? [];

            if($prefix) {
                foreach($resourceRoles as &$resourceRole) {
                    $resourceRole = $resource.'/'.$resourceRole;
                }
            }
        }

        return $resourceRoles;
    }

    /**
     * Check user is authenticated and return his resource roles
     *
     * @param string $resource Default is empty: point to client_id
     *
     * @return array
     */
    public function resources()
    {

        if (! $this->check()) {
            return false;
        }

        $token = Keycloak::retrieveToken();

        if (empty($token) || empty($token['access_token'])) {
            return false;
        }

        $token = new AccessToken($token);
        $token = $token->parseAccessToken();

        return $token['resource_access'] ?? [];
    }

    /**
     * Check user has a role
     *
     * @param array|string $roles
     * @param string $resource Default is empty: point to client_id
     *
     * @return boolean
     */
    public function hasRole($roles, $resource = '')
    {
        return empty(array_diff((array) $roles, $this->resource_roles($resource)));
    }

    /**
     * Check if user has resource access
     *
     * @param string $token
     *
     * @return boolean
     */
    static public function hasResourceAccess($token) {
        $resource = Config::get('keycloak.client_id');

        $parseToken = new AccessToken($token);
        $parseToken = $parseToken->parseAccessToken();

        $resourceRoles = $parseToken['resource_access'] ?? [];
        return $resourceRoles[ $resource ] ?? abort(403, 'Access denied');
    }

    /**
     * Determine if the guard has a user instance.
     *
     * @return boolean
     */
    public function hasUser() {
        return ! is_null($this->user);
    }
}
