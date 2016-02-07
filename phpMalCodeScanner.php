<?php
/*
Plugin Name: php Malicious Code Scanner
Plugin URI: http://www.mikestowe.com/phpmalcode
Description: The php Malicious Code Scanner checks all files for one of the most common malicious code attacks, the eval( base64_decode() ) attack...
Version: 1.3 alpha
Author: Michael Stowe
Author URI: http://www.mikestowe.com
Credits: Based on the idea of Er. Rochak Chauhan (http://www.rochakchauhan.com/), rewritten for use with a cron job
License: GPL-2
*/

// Set to your email:
define('SEND_EMAIL_ALERTS_TO','');


############################################ START CLASS


class phpMalCodeScan {

	public $infected_files = array();
	private $CLI_MODE = false;
	private $OUTPUT_ALERTS = false;
	private $SEND_EMAILS = false;
	private $mail_addr = false;
	
	private $scanned_files = array();
	private $scan_patterns = array(
		'/if\(isset\($_GET\[[a-z][0-9][0-9]+/i',
		'/eval\((base64|eval|\$_|\$\$|\$[A-Za-z_0-9\{]*(\(|\{|\[))/i',
		'/eval\(\$_./i',
		'/<\?php[ \t]+\$_([a-z0-9A-Z]+)=/',
		'/;@ini/i',
		'/.*ineedthispage.*DOORWAYISWORK/i',
		'/.{400,}/i',
	);


	function __construct($mail_addr="") {
		$this->CLI_MODE = (php_sapi_name() == "cli");
		$this->mail_addr = $mail_addr;
		if ( $this->CLI_MODE || empty($mail_addr) || ! $this->SEND_EMAILS) {
			$this->SEND_EMAILS = false;
			$this->OUTPUT_ALERTS = true;
		}

		$this->scan( $this->CLI_MODE ? '.' : dirname(__FILE__) );
		$this->sendalert();
	}


	function scan($dir) {
		$this->scanned_files[] = $dir;
		$files = scandir($dir);

		if(!is_array($files)) {
			throw new Exception('Unable to scan directory ' . $dir . '.  Please make sure proper permissions have been set.');
		}

		foreach($files as $file) {
			if(is_file($dir.'/'.$file) && !in_array($dir.'/'.$file,$this->scanned_files)) {
				$this->check(file_get_contents($dir.'/'.$file),$dir.'/'.$file);
			} elseif(is_dir($dir.'/'.$file) && substr($file,0,1) != '.') {
				$this->scan($dir.'/'.$file);
			}
		}
	}


	function check($contents,$file) {
		$this->scanned_files[] = $file;
		if ( preg_match('/<\?php/',$contents) == false)
			return;

		$infected = false;
		foreach($this->scan_patterns as $pattern) {
			if(preg_match($pattern,$contents)) {
				if($file !== __FILE__) {
					$this->infected_files[] = array('file' => $file, 'pattern_matched' => $pattern);
					$infected = true;
					break;
				}
			}
		}

		if ( substr($file,-4) == '.php' ) {
			$mime = mime_content_type( $file);
			$mime_a = explode('/',$mime);
			if ( $mime_a[0] != "text" ) {
				if ($infected) {
					$pattern_desc = $this->infected_files[count($this->infected_files)-1]['pattern_matched'];
					$this->infected_files[count($this->infected_files)-1]['pattern_matched'] = $pattern_desc." - suspicious mime ($mime)";
				} else {
					$this->infected_files[count($this->infected_files)-1]['pattern_matched'] = array('file' => $file, 'pattern_matched' => "suspicious mime type ($mime)");
				}
			}
		}
	}


	function sendalert() {
		if(count($this->infected_files) != 0) {
			$message = "== MALICIOUS CODE FOUND == \n\n";
			$message .= "The following ".count($this->infected_files)." files appear to be infected: \n";
			foreach($this->infected_files as $inf) {
				$message .= "  -  ".$inf['file'] ."	 [".$inf['pattern_matched']."]\n";
			}
			if($this->SEND_EMAILS)
				mail($this->mail_addr,'Malicious Code Found!',$message,'FROM:');
			if($this->OUTPUT_ALERTS) {
				if (! $this->CLI_MODE )
					print( "<pre>" );
				print( $message );
			}
		}
	}
}


############################################ INITIATE CLASS

ini_set('memory_limit', '-1'); ## Avoid memory errors (i.e in foreachloop)

new phpMalCodeScan(SEND_EMAIL_ALERTS_TO);

