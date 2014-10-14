<?php

use Mockery as m;
use League\OAuth2\Server\Entity\ScopeEntity;
use Lewis\OAuth2\Server\Storage\RedisAuthCode;
use League\OAuth2\Server\Entity\AuthCodeEntity;

class RedisAuthCodeTest extends PHPUnit_Framework_TestCase {


    public function tearDown()
    {
        m::close();
    }


    public function setUp()
    {
        $this->redis = m::mock('Predis\Client');
        $this->server = m::mock('League\OAuth2\Server\AbstractServer');
        $this->storage = new RedisAuthCode($this->redis);
        $this->storage->setServer($this->server);
    }


    public function testGetAuthCodeReturnsNullForInvalidAuthCode()
    {
        $this->redis->shouldReceive('get')->once()->with('oauth:auth:codes:foo')->andReturn(null);

        $this->assertNull($this->storage->get('foo'));
    }


    public function testGetAuthCodeReturnsAuthCodeEntity()
    {
        $this->redis->shouldReceive('get')->once()->with('oauth:auth:codes:foo')->andReturn('{"id":"foo","client_redirect_uri":"bar"}');

        $code = $this->storage->get('foo');

        $this->assertInstanceOf('League\OAuth2\Server\Entity\AuthCodeEntity', $code);
        $this->assertEquals('foo', $code->getId());
        $this->assertEquals('bar', $code->getRedirectUri());
    }


    public function testGetAuthCodeScopes()
    {
        $this->redis->shouldReceive('smembers')->once()->with('oauth:auth:code:scopes:foo')->andReturn([
            ['id' => 'foo'],
            ['id' => 'bar'],
            ['id' => 'baz']
        ]);
        $this->redis->shouldReceive('get')->once()->with('oauth:scopes:foo')->andReturn(['id' => 'foo', 'description' => 'foo']);
        $this->redis->shouldReceive('get')->once()->with('oauth:scopes:bar')->andReturn(null);
        $this->redis->shouldReceive('get')->once()->with('oauth:scopes:baz')->andReturn(['id' => 'baz', 'description' => 'baz']);

        $scopes = $this->storage->getScopes((new AuthCodeEntity($this->server))->setId('foo'));

        $this->assertCount(2, $scopes);
        $this->assertEquals('foo', $scopes[0]->getId());
        $this->assertEquals('baz', $scopes[1]->getId());
    }


    public function testCreateNewAuthCodeEntity()
    {
        $this->redis->shouldReceive('set')->once()->with('oauth:auth:codes:foo', '{"id":"foo","client_redirect_uri":"bar","session_id":1}');
        $this->redis->shouldReceive('sadd')->once()->with('oauth:auth:codes', 'foo');

        $code = $this->storage->create('foo', 1, 1, 'bar');

        $this->assertInstanceOf('League\OAuth2\Server\Entity\AuthCodeEntity', $code);
        $this->assertEquals('foo', $code->getId());
        $this->assertEquals('bar', $code->getRedirectUri());
    }


    public function testAssociatingScopeWithAuthCode()
    {
        $code = (new AuthCodeEntity($this->server))->setId('foo');
        $scope = (new ScopeEntity($this->server))->hydrate(['id' => 'bar']);

        $this->redis->shouldReceive('sadd')->once()->with('oauth:auth:code:scopes:foo', '{"id":"bar"}');

        $this->storage->associateScope($code, $scope);
    }


    public function testDeleteAuthCodeEntity()
    {
        $this->redis->shouldReceive('del')->once()->with('oauth:auth:codes:foo');
        $this->redis->shouldReceive('del')->once()->with('oauth:auth:code:scopes:foo');
        $this->redis->shouldReceive('srem')->once()->with('oauth:auth:codes', 'foo');

        $code = (new AuthCodeEntity($this->server))->setId('foo');

        $this->storage->delete($code);
    }


}
