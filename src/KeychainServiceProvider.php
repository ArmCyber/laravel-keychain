<?php

namespace ArmCyber\Keychain;

use ArmCyber\Keychain\Encryptors\GeneralEncryptor;
use ArmCyber\Keychain\Encryptors\PairEncryptor;
use ArmCyber\Keychain\Encryptors\PasswordEncryptor;
use Illuminate\Support\ServiceProvider;

class KeychainServiceProvider extends ServiceProvider
{
    /**
     * Register any package services.
     */
    public function register(): void
    {
        $this->registerServiceContainers();
        $this->registerConfig();
    }

    /**
     * Bootstrap any package services.
     */
    public function boot(): void
    {
        //
    }

    /**
     * Register package service containers.
     *
     * @return void
     */
    private function registerServiceContainers(): void
    {
        $this->app->bind(Keychain::class, fn() => Keychain::current());
        $this->app->singleton(GeneralEncryptor::class);
        $this->app->singleton(PairEncryptor::class);
        $this->app->singleton(PasswordEncryptor::class);
    }

    /**
     * Register package configurations.
     *
     * @return void
     */
    private function registerConfig(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/keychain.php', 'keychain');
    }
}
