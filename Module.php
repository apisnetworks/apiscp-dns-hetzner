<?php declare(strict_types=1);

	/**
	 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
	 *
	 * MIT License
	 *
	 * Written by Matt Saladna <matt@apisnetworks.com>, August 2020
	 */

	namespace Opcenter\Dns\Providers\Hetzner;

	use GuzzleHttp\Exception\ClientException;
	use Module\Provider\Contracts\ProviderInterface;
	use Opcenter\Crypto\Keyring;
	use Opcenter\Crypto\KeyringTrait;
	use Opcenter\Dns\Record as BaseRecord;

	class Module extends \Dns_Module implements ProviderInterface
	{
		use \NamespaceUtilitiesTrait;
		use KeyringTrait;

		/**
		 * apex markers are marked with @
		 */
		protected const HAS_ORIGIN_MARKER = true;
		protected const HAS_CONTIGUOUS_LIMIT = true;

		protected static $permitted_records = [
			/* 'DS' // broken implementation , */
			'A',
			'AAAA',
			'CAA',
			'CNAME',
			'HINFO',
			'MX',
			// doesn't support editing root
			'NS',
			'RP',
			'SRV',
			'TLSA',
			'TXT'
		];

		public const SHOW_NS_APEX = false;

		protected $metaCache = [];

		// @var array API credentials
		private $key;

		public function __construct()
		{
			parent::__construct();
			$this->key = $this->getServiceValue('dns', 'key', DNS_PROVIDER_KEY);
			if (Keyring::is($this->key)) {
				$this->key = $this->readKeyringValue($this->key);
			}

			if (strlen($this->key) !== 64) {
				warn("DNS management unavailable until migration to new Hetzner API key");
				$this->key = null;
			}
		}

		/**
		 * Add a DNS record
		 *
		 * @param string $zone
		 * @param string $subdomain
		 * @param string $rr
		 * @param string $param
		 * @param int    $ttl
		 * @return bool
		 */
		public function add_record(
			string $zone,
			string $subdomain,
			string $rr,
			string $param,
			int $ttl = self::DNS_TTL
		): bool {
			if (!$this->canonicalizeRecord($zone, $subdomain, $rr, $param, $ttl)) {
				return false;
			}

			if (!$this->owned_zone($zone)) {
				return error("Domain `%s' not owned by account", $zone);
			}
			$api = $this->makeApi();
			$record = new Record($zone, [
				'name'      => $subdomain,
				'rr'        => $rr,
				'parameter' => $param,
				'ttl'       => $ttl
			]);

			try {
				$zoneid = $this->getZoneId($zone);
				$ret = $api->do('POST', "zones/{$zoneid}/rrsets/{$subdomain}/{$rr}/actions/add_records",
					$this->formatRecord($record)
				);
				$this->addCache($record);
			} catch (ClientException $e) {
				return error("Failed to create record `%s': %s", (string)$record, $this->renderMessage($e));
			}

			return (bool)$ret;
		}

		/**
		 * @inheritDoc
		 */
		public function remove_record(string $zone, string $subdomain, string $rr, string $param = ''): bool
		{
			if (!$this->canonicalizeRecord($zone, $subdomain, $rr, $param, $ttl)) {
				return false;
			}

			if (!$this->owned_zone($zone)) {
				return error("Domain `%s' not owned by account", $zone);
			}
			$api = $this->makeApi();
			$id = $this->getRecordId($r = new Record($zone,
				['name' => $subdomain, 'rr' => $rr, 'parameter' => $param]));
			if (!$id) {
				$fqdn = ltrim(implode('.', [$subdomain, $zone]), '.');
				return error("Record `%s' (rr: `%s', param: `%s') does not exist", $fqdn, $rr, $param);
			}

			// ref: DNS > Zone RRSet Actions
			$endpoint = "zones/{$zone}/rrsets/{$subdomain}/{$rr}" . ($param ?  "/actions/remove_records" : "");
			$params = $param ? $this->formatRecord($r) : null;
			try {
				$api->do($param ? 'POST' : 'DELETE', $endpoint, $params);
			} catch (ClientException $e) {
				$fqdn = ltrim(implode('.', [$subdomain, $zone]), '.');
				return error(
					"Failed to delete record `%(fqdn)s' type %(rr)s: %(err)s",
					['fqdn' => $fqdn, 'rr' => $rr, 'err' => $this->formatError($e)]
				);
			}

			if (!$param) {
				array_forget($this->zoneCache[$r->getZone()], $this->getCacheKey($r));
			} else {
				array_forget_first(
					$this->zoneCache[$r->getZone()],
					$this->getCacheKey($r),
					static function ($v) use ($id) {
						return $v->getMeta('id') === $id;
					}
				);
			}

			return $api->getResponse()->getStatusCode() === 201;
		}

		private function formatError(ClientException $e): string
		{
			$msg = $e->getResponse()->getBody()->getContents();
			if (!$json = json_decode($msg, true)) {
				return 'NULL';
			}

			return $json['error']['message'] ?? 'NULL';
		}

		/**
		 * Add DNS zone to service
		 *
		 * @param string $domain
		 * @param string $ip
		 * @return bool
		 */
		public function add_zone_backend(string $domain, string $ip): bool
		{
			/**
			 * @var Zones $api
			 */
			$api = $this->makeApi();
			try {
				$api->do('POST', 'zones', [
					'name'    => $domain,
					'ttl'     => self::DNS_TTL,
					'mode'    => 'primary',
				]);
			} catch (ClientException $e) {
				return error("Failed to add zone `%s', error: %s", $domain, $this->renderMessage($e));
			}

			return true;
		}

		public function verified(string $domain): bool
		{
			$cache = \Cache_Super_Global::spawn($this->getAuthContext());
			if (true === ($verified = $cache->hGet("dns:hetzner.vrfy", $domain))) {
				return $verified;
			}

			if ($verified = ($this->getZoneMeta($domain, 'authoritative_nameservers')['delegation_status'] === 'valid')) {
				$cache->hSet("dns:hetzner.vrfy", $domain, $verified);
			}

			return $verified;
		}

		public function verify(string $domain): bool
		{
			return warn("This API does not support verification");
		}

		/**
		 * Remove DNS zone from nameserver
		 *
		 * @param string $domain
		 * @return bool
		 */
		public function remove_zone_backend(string $domain): bool
		{
			$api = $this->makeApi();
			try {
				$domainid = $this->getZoneId($domain);
				if (!$domainid) {
					return warn("Domain ID not found - `%s' already removed?", $domain);
				}
				$api->do('DELETE', "zones/{$domainid}");
			} catch (ClientException $e) {
				return error("Failed to remove zone `%s', error: %s", $domain, $this->renderMessage($e));
			}

			return true;
		}

		/**
		 * Get raw zone data
		 *
		 * @param string $domain
		 * @return null|string
		 */
		protected function zoneAxfr(string $domain): ?string
		{
			// @todo hold records in cache and synthesize AXFR
			$client = $this->makeApi();

			try {
				if (!$domainid = $this->getZoneId($domain)) {
					return null;
				}
				$records = $this->populateZoneMetaCache($domainid);
				$records = $records['rrsets'];

				$soa = array_first($records, static function ($v) {
					return $v['type'] === 'SOA';
				});

				// fairly safe to assume everything provisioned in Hetzner will contain a properly formatted SOA
				$soa = array_pop($soa['records']);

				$ttldef = (int)array_get(preg_split('/\s+/', $soa['value'] ?? ''), 6, static::DNS_TTL);
				$preamble = [];
				if ($soa) {
					$preamble = [
						"{$domain}.\t{$ttldef}\tIN\tSOA\t{$soa['value']}",
					];
				}
				foreach ($this->get_hosting_nameservers($domain) as $ns) {
					$preamble[] = "{$domain}.\t{$ttldef}\tIN\tNS\t{$ns}.";
				}

			} catch (ClientException $e) {
				if ($e->getResponse()->getStatusCode() === 404) {
					// zone doesn't exist
					return null;
				}

				error('Failed to transfer DNS records from Hetzner - try again later. Response code: %d',
					$e->getResponse()->getStatusCode());

				return null;
			}
			$this->zoneCache[$domain] = [];
			$defaultTtl = $this->getZoneMeta($domain, 'ttl');
			foreach ($records as $r) {
				switch ($r['type']) {
					case 'SOA':
						continue 2;
					default:
						$parameterValues = array_flatten(array_column($r['records'], 'value'));
				}
				foreach ($parameterValues as $parameter) {
					$hostname = ltrim($r['name'] . '.' . $domain, '@.') . '.';
					$preamble[] = $hostname . "\t" . ($r['ttl'] ?? $defaultTtl) . "\tIN\t" .
						$r['type'] . "\t" . $parameter;

					$this->addCache(new Record($domain,
						[
							'name'      => $r['name'],
							'rr'        => $r['type'],
							'ttl'       => $r['ttl'] ?? $defaultTtl,
							'parameter' => $parameter,
							'meta'      => [
								'id' => $r['id']
							]
						]
					));
				}
			}
			$axfrrec = implode("\n", $preamble);
			$this->zoneCache[$domain]['text'] = $axfrrec;

			return $axfrrec;
		}

		protected function populateZoneMetaCache(string $domainid, int $pagenr = 1)
		{
			// @todo support > 100 domains
			$api = $this->makeApi();
			if ($pagenr === 1) {
				$raw = $api->do('GET', "zones/{$domainid}");
				if (empty($raw)) {
					return null;
				}
				$this->metaCache[$domainid] = $raw['zone'];
				$this->metaCache[$domainid]['rrsets'] = [];
			}

			$raw = $api->do('GET', "zones/{$domainid}/rrsets?per_page=100&page={$pagenr}");
			$this->metaCache[$domainid]['rrsets'] = array_merge($this->metaCache[$domainid]['rrsets'], $raw['rrsets']);
			$pagecnt = $raw['meta']['pagination']['last_page'];
			if ($pagenr < $pagecnt && $raw['rrsets']) {
				return $this->populateZoneMetaCache($domainid, ++$pagenr);
			}

			return $this->metaCache[$domainid];
		}


		/**
		 * Create a Hetzner API client
		 *
		 * @return Api
		 */
		private function makeApi(): Api
		{
			return new Api($this->key);
		}

		/**
		 * Get internal Hetzner zone ID
		 *
		 * @param string $domain
		 * @return null|string
		 */
		protected function getZoneId(string $domain): ?string
		{
			return $domain;
		}

		/**
		 * Get zone meta information
		 *
		 * @param string $domain
		 * @param string $key
		 * @return mixed|null
		 */
		private function getZoneMeta(string $domain, string $key = null)
		{
			if (!isset($this->metaCache[$domain])) {
				$this->populateZoneMetaCache($domain);
			}
			if (!$key) {
				return $this->metaCache[$domain] ?? null;
			}

			return $this->metaCache[$domain][$key] ?? null;
		}

		/**
		 * Get hosting nameservers
		 *
		 * @param string|null $domain
		 * @return array
		 */
		public function get_hosting_nameservers(string $domain = null): array
		{
			return array_map(static fn($domain) => rtrim($domain, '.'), $this->getZoneMeta($domain, 'authoritative_nameservers')['assigned'] ?? []);
		}

		/**
		 * Modify a DNS record
		 *
		 * @param string $zone
		 * @param Record $old
		 * @param Record $new
		 * @return bool
		 */
		protected function atomicUpdate(string $zone, BaseRecord $old, BaseRecord $new): bool
		{
			if (!$this->canonicalizeRecord($zone, $old['name'], $old['rr'], $old['parameter'], $old['ttl'])) {
				return false;
			}

			if (!$this->getRecordId($old)) {
				return error("failed to find record ID in Hetzner zone `%s' - does `%s' (rr: `%s', parameter: `%s') exist?",
					$zone, $old['name'], $old['rr'], $old['parameter']);
			}
			if (!$this->canonicalizeRecord($zone, $new['name'], $new['rr'], $new['parameter'], $new['ttl'])) {
				return false;
			}

			$api = $this->makeApi();
			try {
				$merged = clone $old;
				$new = $merged->merge($new);

				// determine if 2 API calls are necessary for rrset losing member
				$removalSet = (clone $old)->merge(new Record($zone, [
					'parameter' => null, 'rr' => $new['rr'], 'name' => $new['name'], 'ttl' => $old['ttl']]));

				// TTL change is a separate call...
				$ttlChange = $new['ttl'] !== $old['ttl'];

				// reapply canonicalization, transform '' => @ for example
				$this->canonicalizeRecord($removalSet['zone'], $removalSet['name'], $removalSet['rr'], $removalSet['parameter'], $removalSet['ttl']);

				$id = $this->getRecordId($old);
				$oldset = $old->is($removalSet) ? null : array_filter(
					$this->getMatchingRecordsFromCache($old),
					static fn($x) => !$x->is($old)
				);

				$newset = array_filter(
					$this->getMatchingRecordsFromCache($new),
					static fn($x) => !$x->is($old)
				);

				$newset[] = $new;
				$flattenizer = function(int $i, Record $x) {
					return [$i, ['value' => $this->formatRecord($x)['records'][0]['value']]];
				};
				$built = [
					'new' => ['records' => array_values(array_build($newset, $flattenizer(...)))],
					'old' => !is_null($oldset) ?
						['records' => array_values(array_build($oldset, $flattenizer(...)))] :
						null
				];

				if (count($built['new']['records']) === 1 && !empty($built['old']['records'])) {
					// set_records does not create rrset
					$ret = $this->add_record($zone, $new['name'], $new['rr'], $new['parameter'], $new['ttl'] ?? static::DNS_TTL);
					if (!$ret) {
						return false;
					}
				} else {
					$api->do('POST', "zones/{$zone}/rrsets/{$new['name']}/{$new['rr']}/actions/set_records", $built['new']);
				}
				// crosses subdomain/RR boundaries
				if (!is_null($built['old'])) {
					if (empty($built['old']['records'])) {
						// no records left
						$api->do('DELETE', "zones/{$zone}/rrsets/{$old['name']}/{$old['rr']}");
					} else {
						$api->do('POST', "zones/{$zone}/rrsets/{$old['name']}/{$old['rr']}/actions/set_records",
							$built['old']);
					}
				}
				if ($ttlChange) {
					$api->do('POST', "zones/{$zone}/rrsets/{$new['name']}/{$new['rr']}/actions/change_ttl", ['ttl' => $new['ttl']]);
				}
			} catch (ClientException $e) {
				return error("Failed to update record `%s' on zone `%s' (old - rr: `%s', param: `%s'; new - rr: `%s', param: `%s'): %s",
					$old['name'],
					$zone,
					$old['rr'],
					$old['parameter'], $new['name'] ?? $old['name'], $new['parameter'] ?? $old['parameter'],
					$this->renderMessage($e)
				);
			}
			array_forget_first(
				$this->zoneCache[$old->getZone()],
				$this->getCacheKey($old),
				static function ($v) use ($id) {
					return $v->getMeta('id') === $id;
				}
			);

			$this->addCache($new);

			return true;
		}

		/**
		 * Format a Hetzner record prior to sending
		 *
		 * @param Record $r
		 * @return array
		 */
		protected function formatRecord(Record $r): ?array
		{
			$args = [
				'name' => $r['name'] ?: '@',
				'type' => strtoupper($r['rr']),
				'ttl'  => $r['ttl'] ?? static::DNS_TTL
			];
			switch ($args['type']) {
				case 'CAA':
					return $args + ['records' => [
							['value' => implode(' ', [
									$r->getMeta('flags'),
									$r->getMeta('tag'),
									trim($r->getMeta('data'), '"')
								])
							]
						]
					];
				default:
					return $args + ['records' => [['value' => $r['parameter']]]];
			}
		}

		/**
		 * Extract JSON message if present
		 *
		 * @param ClientException $e
		 * @return string
		 */
		private function renderMessage(ClientException $e): string
		{

			$body = \Error_Reporter::silence(static function () use ($e) {
				return \json_decode($e->getResponse()->getBody()->getContents(), true);
			});
			if (!$body || !($reason = array_get($body, 'error.message'))) {
				return $e->getMessage();
			}

			return $reason;
		}

		/**
		 * CNAME cannot be present in root
		 *
		 * @return bool
		 */
		protected function hasCnameApexRestriction(): bool
		{
			return false;
		}
	}