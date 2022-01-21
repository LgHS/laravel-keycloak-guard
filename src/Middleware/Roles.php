<?php

namespace Lghs\KeycloakWebGuard\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;
use Lghs\KeycloakWebGuard\Exceptions\KeycloakRolesException;

class KeycloakRoles extends KeycloakAuthenticated
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle($request, Closure $next, ...$guards)
    {
        if (empty($guards) && Auth::check()) {
            return $next($request);
        }

        $guards = explode('|', ($guards[0] ?? ''));
        if (Auth::hasRole($guards)) {
            return $next($request);
        }

        throw new KeycloakRolesException(
            'Unauthenticated.', $guards, $this->redirectTo($request)
        );
    }
}
