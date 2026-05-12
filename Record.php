<?php declare(strict_types=1);
	/**
	 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
	 *
	 * Unauthorized copying of this file, via any medium, is
	 * strictly prohibited without consent. Any dissemination of
	 * material herein is prohibited.
	 *
	 * For licensing inquiries email <licensing@apisnetworks.com>
	 *
	 * Written by Matt Saladna <matt@apisnetworks.com>, August 2020
	 */

	namespace Opcenter\Dns\Providers\Hetzner;

	class Record extends \Opcenter\Dns\Record
	{
		public function __construct(string $zone, array $args)
		{
			if (substr($args['name'], -strlen($zone)-1) === ".{$zone}") {
				$args['name'] = substr($args['name'], 0, -strlen($zone)-1);
			}
			parent::__construct($zone, $args);
			$this->setMeta('id', "{$this->name}/{$this->rr}");
		}

		protected function formatTxt() {
			// remove empty labels
			if (!empty($this->parameter)) {
				$this->parameter = '"' . trim(str_replace([' "" '], [''], (string)$this->parameter), ' "') . '"';
			}
		}


	}