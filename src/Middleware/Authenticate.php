<?php

namespace Lghs\KeycloakGuard\Middleware;

use Illuminate\Auth\Middleware\Authenticate as ExtendedAuthenticate;

class Authenticate extends ExtendedAuthenticate
{
    /**
     * Redirect user if it's not authenticated.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    protected function redirectTo($request)
    {
        $url = config('keycloak.redirect_guest', 'keycloak.login');
        return route($url);
    }
}
