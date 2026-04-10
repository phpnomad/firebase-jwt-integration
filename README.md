# phpnomad/firebase-jwt-integration

[![Latest Version](https://img.shields.io/packagist/v/phpnomad/firebase-jwt-integration.svg)](https://packagist.org/packages/phpnomad/firebase-jwt-integration)
[![Total Downloads](https://img.shields.io/packagist/dt/phpnomad/firebase-jwt-integration.svg)](https://packagist.org/packages/phpnomad/firebase-jwt-integration)
[![PHP Version](https://img.shields.io/packagist/php-v/phpnomad/firebase-jwt-integration.svg)](https://packagist.org/packages/phpnomad/firebase-jwt-integration)
[![License](https://img.shields.io/packagist/l/phpnomad/firebase-jwt-integration.svg)](https://packagist.org/packages/phpnomad/firebase-jwt-integration)

Integrates the [firebase/php-jwt](https://github.com/firebase/php-jwt) library with `phpnomad/auth`'s `JwtStrategy` interface. It provides a single concrete strategy that encodes payloads into HS256-signed JSON Web Tokens and decodes them back into arrays, translating firebase/php-jwt's exception types into `PHPNomad\Auth\Exceptions\JwtException` so the rest of your application only has to catch one thing.

## Installation

```bash
composer require phpnomad/firebase-jwt-integration
```

## What This Provides

- A `FirebaseJwt` strategy class that implements `PHPNomad\Auth\Interfaces\JwtStrategy` using `firebase/php-jwt`, with HS256 for both encoding and verification.
- Exception translation that maps `ExpiredException`, `SignatureInvalidException`, `BeforeValidException`, and the standard PHP value errors into `PHPNomad\Auth\Exceptions\JwtException` with descriptive messages.

## Requirements

- `phpnomad/auth ^1.0` for the `JwtStrategy` interface and its `JwtException` type.
- `firebase/php-jwt ^6.10` as the underlying JWT library.

## Usage

Bind `FirebaseJwt` to the `JwtStrategy` interface inside one of your bootstrapper initializers. Any service that depends on `JwtStrategy` will then receive this implementation without knowing which library is wired in behind it.

```php
<?php

namespace MyApp\Strategies;

use PHPNomad\Auth\Interfaces\JwtStrategy;
use PHPNomad\JWT\Firebase\Integration\Strategies\FirebaseJwt;
use PHPNomad\Loader\Interfaces\HasClassDefinitions;

final class JwtInitializer implements HasClassDefinitions
{
    public function getClassDefinitions(): array
    {
        return [
            FirebaseJwt::class => JwtStrategy::class,
        ];
    }
}
```

With that binding in place, a service can take `JwtStrategy` as a constructor dependency and call `$jwt->encode($payload, $secret)` or `$jwt->decode($token, $secret)` without ever referencing `FirebaseJwt` directly.

## Documentation

See the bootstrapping and strategy binding guides at [phpnomad.com](https://phpnomad.com). For details on the underlying library, configuration options, and supported algorithms, see [firebase/php-jwt](https://github.com/firebase/php-jwt).

## License

Released under the MIT License. See [LICENSE.txt](LICENSE.txt).
