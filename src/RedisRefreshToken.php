<?php

namespace Lewis\OAuth2\Server\Storage;

use League\OAuth2\Server\Entity\RefreshTokenEntity;
use League\OAuth2\Server\Storage\RefreshTokenInterface;

class RedisRefreshToken extends RedisAdapter implements RefreshTokenInterface
{
    /**
     * Get refresh token from Redis storage.
     *
     * @param  string  $token
     * @return \League\OAuth2\Server\Entity\RefreshTokenEntity|null
     */
    public function get($token)
    {
        if (! $refresh = $this->getValue($token, 'oauth_refresh_tokens')) {
            return null;
        }

        if ($refresh['expire_time'] < time()) {
            return null;
        }

        return (new RefreshTokenEntity($this->server))
            ->setId($refresh['id'])
            ->setExpireTime($refresh['expire_time'])
            ->setAccessTokenId($refresh['access_token_id']);
    }

    /**
     * Creates a new refresh token in Redis storage.
     *
     * @param  string  $token
     * @param  int  $expireTime
     * @param  string  $accessToken
     */
    public function create($token, $expireTime, $accessToken)
    {
        $payload = [
            'id'              => $token,
            'expire_time'     => $expireTime,
            'access_token_id' => $accessToken
        ];

        $this->setValue($token, 'oauth_refresh_tokens', $payload);
        $this->pushSet(null, 'oauth_refresh_tokens', $token);

        return (new RefreshTokenEntity($this->getServer()))
               ->setId($token)
               ->setExpireTime($expireTime);
    }

    /**
     * Delete a refresh token from Redis storage.
     *
     * @param  \League\OAuth2\Server\Entity\RefreshTokenEntity  $token
     * @return void
     */
    public function delete(RefreshTokenEntity $token)
    {
        // Deletes the access token entry.
        $this->deleteKey($token->getId(), 'oauth_refresh_tokens');

        // Deletes the access token entry from the access tokens set.
        $this->deleteSet(null, 'oauth_refresh_tokens', $token->getId());
    }
}
