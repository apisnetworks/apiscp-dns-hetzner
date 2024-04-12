<?php declare(strict_types=1);

	/**
	 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
	 *
	 * MIT License
	 *
	 * Written by Matt Saladna <matt@apisnetworks.com>, August 2020
	 */

	namespace Opcenter\Dns\Providers\Hetzner;

	use GuzzleHttp\Exception\RequestException;
	use Opcenter\Dns\Contracts\ServiceProvider;
	use Opcenter\Service\ConfigurationContext;

	class Validator implements ServiceProvider
	{
		public function valid(ConfigurationContext $ctx, &$var): bool
		{
			return ctype_alnum($var) && strlen($var) >= 32 && static::keyValid((string)$var);
		}

		public static function keyValid(string $key): bool
		{
			try {
				(new Api($key))->do('GET', 'zones');
			} catch (RequestException $e) {
				$reason = $e->getMessage();
				if (null !== ($response = $e->getResponse())) {
					$response = \json_decode($response->getBody()->getContents(), true);
					$reason = array_get($response, 'error.message', 'Invalid key');
				}

				if ($reason === 'zone not found') {
					// bug in Hetzner implementation
					return true;
				}

				return error('%(provider)s key validation failed: %(reason)s', [
					'provider' => 'Hetzner',
					'reason'   => $reason
				]);
			}

			return true;
		}
	}