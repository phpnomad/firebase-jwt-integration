<?php

namespace PHPNomad\JWT\Firebase\Integration\Strategies;

use DomainException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;
use InvalidArgumentException;
use PHPNomad\Auth\Exceptions\JwtException;
use PHPNomad\Auth\Interfaces\JwtStrategy;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use UnexpectedValueException;

class FirebaseJwt implements JwtStrategy
{
    /**
     * @inheritDoc
     */
    public function encode(array $payload, string $secret): string
    {
        return JWT::encode($payload, $secret, 'HS256');
    }

    /**
     * @inheritDoc
     */
    public function decode(string $jwt, string $secret): array
    {
        try {
            // Decode the JWT using the secret key
            return (array) JWT::decode($jwt, new Key($secret, 'HS256'));
        } catch (ExpiredException $e) {
            throw new JwtException("Token has expired", 0, $e);
        } catch (SignatureInvalidException $e) {
            throw new JwtException("Token signature is invalid", 0, $e);
        } catch (BeforeValidException $e) {
            throw new JwtException("Token is not yet valid", 0, $e);
        } catch (UnexpectedValueException | DomainException | InvalidArgumentException $e) {
            throw new JwtException("Invalid token: " . $e->getMessage(), 0, $e);
        }
    }
}