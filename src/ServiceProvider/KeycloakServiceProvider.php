<?php

namespace Lghs\KeycloakWebGuard;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;
use Lghs\KeycloakWebGuard\Auth\Guard\Keycloak;
use Lghs\KeycloakWebGuard\Auth\UserProvider;
use Lghs\KeycloakWebGuard\Middleware\Authenticate;
use Lghs\KeycloakWebGuard\Middleware\Roles;
use Lghs\KeycloakWebGuard\Models\User;
use Lghs\KeycloakWebGuard\Services\KeycloakService;

class KeycloakWebGuardServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        // Configuration
        $config = __DIR__ . '/../config/keycloak.php';

        $this->publishes([$config => config_path('keycloak.php')], 'config');
        $this->mergeConfigFrom($config, 'keycloak');

        // User Provider
        Auth::provider('keycloak-users', function($app, array $config) {
            return new UserProvider($config['model']);
        });

        // Gate
        Gate::define('keycloak', function ($user, $roles, $resource = '') {
            return $user->hasRole($roles, $resource) ?: null;
        });
    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        // Keycloak Web Guard
        Auth::extend('keycloak', function ($app, $name, array $config) {
            $provider = Auth::createUserProvider($config['provider']);
            return new Keycloak($provider, $app->request);
        });

        // Facades
        $this->app->bind('keycloak', function($app) {
            return $app->make(KeycloakService::class);
        });

        // Routes
        $this->registerRoutes();

        // Middleware Group
        $this->app['router']->middlewareGroup('keycloak', [
            StartSession::class,
            Authenticate::class,
        ]);

        // Add Middleware "keycloak-roles"
        $this->app['router']->aliasMiddleware('keycloak-roles', Roles::class);

        // Bind for client data
        $this->app->when(KeycloakService::class)->needs(ClientInterface::class)->give(function() {
            return new Client(Config::get('keycloak.guzzle_options', []));
        });
    }

    /**
     * Register the authentication routes for keycloak.
     *
     * @return void
     */
    private function registerRoutes()
    {
        $defaults = [
            'login' => 'login',
            'logout' => 'logout',
            'register' => 'register',
            'callback' => 'callback',
        ];

        $routes = Config::get('keycloak.routes', []);
        $routes = array_merge($defaults, $routes);

        // Register Routes
        $router = $this->app->make('router');

        if (! empty($routes['login'])) {
            $router->middleware('web')->get($routes['login'], 'Lghs\KeycloakWebGuard\Controllers\AuthController@login')->name('keycloak.login');
        }

        if (! empty($routes['logout'])) {
            $router->middleware('web')->get($routes['logout'], 'Lghs\KeycloakWebGuard\Controllers\AuthController@logout')->name('keycloak.logout');
        }

        if (! empty($routes['register'])) {
            $router->middleware('web')->get($routes['register'], 'Lghs\KeycloakWebGuard\Controllers\AuthController@register')->name('keycloak.register');
        }

        if (! empty($routes['callback'])) {
            $router->middleware('web')->get($routes['callback'], 'Lghs\KeycloakWebGuard\Controllers\AuthController@callback')->name('keycloak.callback');
        }
    }
}
