<?php

namespace Lghs\KeycloakGuard\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Lghs\KeycloakGuard\Exceptions\CallbackException;
use Lghs\KeycloakGuard\Facades\Keycloak;

class AuthController extends Controller
{
    /**
     * Redirect to login
     *
     * @return view
     */
    public function login()
    {
        $url = Keycloak::getLoginUrl();
        Keycloak::saveState();

        return redirect($url);
    }

    /**
     * Redirect to logout
     *
     * @return view
     */
    public function logout()
    {
        Keycloak::forgetToken();

        $url = Keycloak::getLogoutUrl();
        return redirect($url);
    }

    /**
     * Redirect to register
     *
     * @return view
     */
    public function register()
    {
        $url = Keycloak::getRegisterUrl();
        return redirect($url);
    }

    /**
     * Keycloak callback page
     *
     * @return view
     * @throws CallbackException
     *
     */
    public function callback(Request $request)
    {
        // Check for errors from Keycloak
        if (! empty($request->input('error'))) {
            $error = $request->input('error_description');
            $error = ($error) ?: $request->input('error');

            throw new CallbackException($error);
        }

        // Check given state to mitigate CSRF attack
        $state = $request->input('state');
        if (empty($state) || ! Keycloak::validateState($state)) {
            Keycloak::forgetState();

            throw new CallbackException('Invalid state');
        }

        // Change code for token
        $code = $request->input('code');
        if (! empty($code)) {
            $token = Keycloak::getAccessToken($code);

            if (Auth::validate($token)) {
                $url = config('keycloak.redirect_url', '/admin');
                return redirect()->intended($url);
            }
        }

        return redirect(route('keycloak.login'));
    }
}
