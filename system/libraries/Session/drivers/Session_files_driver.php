<?php
/**
 * CodeIgniter
 *
 * An open source application development framework for PHP
 *
 * This content is released under the MIT License (MIT)
 *
 * @package	CodeIgniter
 */

defined('BASEPATH') OR exit('No direct script access allowed');

/**
 * CodeIgniter Session Files Driver
 *
 * @package	CodeIgniter
 * @subpackage	Libraries
 * @category	Sessions
 */
class CI_Session_files_driver extends CI_Session_driver implements SessionHandlerInterface {

	/**
	 * Save path
	 *
	 * @var	string
	 */
	protected $_save_path;

	/**
	 * File handle
	 *
	 * @var	resource
	 */
	protected $_file_handle;

	/**
	 * File name
	 *
	 * @var	string
	 */
	protected $_file_path;

	/**
	 * File new flag
	 *
	 * @var	bool
	 */
	protected $_file_new;

	/**
	 * Validate SID regular expression
	 *
	 * @var	string
	 */
	protected $_sid_regexp;

	/**
	 * mbstring.func_overload flag
	 *
	 * @var	bool
	 */
	protected static $func_overload;

	/**
	 * Class constructor
	 *
	 * @param	array	$params	Configuration parameters
	 * @return	void
	 */
	public function __construct(&$params)
	{
		parent::__construct($params);

		if (isset($this->_config['save_path']))
		{
			$this->_config['save_path'] = rtrim($this->_config['save_path'], '/\\');
			ini_set('session.save_path', $this->_config['save_path']);
		}
		else
		{
			log_message('debug', 'Session: "sess_save_path" is empty; using "session.save_path" value from php.ini.');
			$this->_config['save_path'] = rtrim(ini_get('session.save_path'), '/\\');
		}

		$this->_sid_regexp = $this->_config['_sid_regexp'];

		isset(self::$func_overload) OR self::$func_overload = (extension_loaded('mbstring') && ini_get('mbstring.func_overload'));
	}

	#[\ReturnTypeWillChange] // Suppress warning temporarily in PHP 8.x
	public function open($save_path, $name): bool // Add return type bool
	{
		if (!is_dir($save_path))
		{
			if (!mkdir($save_path, 0700, TRUE))
			{
				throw new Exception("Session: Configured save path '".$this->_config['save_path']."' is not a directory, doesn't exist or cannot be created.");
			}
		}
		elseif (!is_writable($save_path))
		{
			throw new Exception("Session: Configured save path '".$this->_config['save_path']."' is not writable by the PHP process.");
		}

		$this->_config['save_path'] = $save_path;
		$this->_file_path = $this->_config['save_path'].DIRECTORY_SEPARATOR
			.$name 
			.($this->_config['match_ip'] ? md5($_SERVER['REMOTE_ADDR']) : '');

		$this->php5_validate_id();

		return true; // Return boolean value
	}

	#[\ReturnTypeWillChange] // Suppress warning temporarily
	public function read($session_id): string
	{
		if ($this->_file_handle === NULL)
		{
			$this->_file_new = !file_exists($this->_file_path.$session_id);

			if (($this->_file_handle = fopen($this->_file_path.$session_id, 'c+b')) === FALSE)
			{
				log_message('error', "Session: Unable to open file '".$this->_file_path.$session_id."'.");
				return '';
			}

			if (flock($this->_file_handle, LOCK_EX) === FALSE)
			{
				log_message('error', "Session: Unable to obtain lock for file '".$this->_file_path.$session_id."'.");
				fclose($this->_file_handle);
				$this->_file_handle = NULL;
				return '';
			}

			$this->_session_id = $session_id;

			if ($this->_file_new)
			{
				chmod($this->_file_path.$session_id, 0600);
				$this->_fingerprint = md5('');
				return '';
			}
		}
		elseif ($this->_file_handle === FALSE)
		{
			return '';
		}
		else
		{
			rewind($this->_file_handle);
		}

		$session_data = '';
		for ($read = 0, $length = filesize($this->_file_path.$session_id); $read < $length; $read += strlen($buffer))
		{
			if (($buffer = fread($this->_file_handle, $length - $read)) === FALSE)
			{
				break;
			}

			$session_data .= $buffer;
		}

		$this->_fingerprint = md5($session_data);
		return $session_data;
	}

	#[\ReturnTypeWillChange] // Suppress warning temporarily
	public function write($session_id, $session_data): bool
	{
		if ($session_id !== $this->_session_id && ($this->close() === false OR $this->read($session_id) === false))
		{
			return false;
		}

		if (!is_resource($this->_file_handle))
		{
			return false;
		}
		elseif ($this->_fingerprint === md5($session_data))
		{
			return (!$this->_file_new && !touch($this->_file_path.$session_id))
				? false
				: true;
		}

		if (!$this->_file_new)
		{
			ftruncate($this->_file_handle, 0);
			rewind($this->_file_handle);
		}

		if (($length = strlen($session_data)) > 0)
		{
			for ($written = 0; $written < $length; $written += $result)
			{
				if (($result = fwrite($this->_file_handle, substr($session_data, $written))) === FALSE)
				{
					break;
				}
			}

			if (!is_int($result))
			{
				$this->_fingerprint = md5(substr($session_data, 0, $written));
				log_message('error', 'Session: Unable to write data.');
				return false;
			}
		}

		$this->_fingerprint = md5($session_data);
		return true;
	}

	#[\ReturnTypeWillChange] // Suppress warning temporarily
	public function close(): bool
	{
		if (is_resource($this->_file_handle))
		{
			flock($this->_file_handle, LOCK_UN);
			fclose($this->_file_handle);

			$this->_file_handle = $this->_file_new = $this->_session_id = NULL;
		}

		return true;
	}

	#[\ReturnTypeWillChange] // Suppress warning temporarily
	public function destroy($session_id): bool
	{
		if ($this->close() === true)
		{
			if (file_exists($this->_file_path.$session_id))
			{
				$this->_cookie_destroy();
				return unlink($this->_file_path.$session_id)
					? true
					: false;
			}

			return true;
		}
		elseif ($this->_file_path !== NULL)
		{
			clearstatcache();
			if (file_exists($this->_file_path.$session_id))
			{
				$this->_cookie_destroy();
				return unlink($this->_file_path.$session_id)
					? true
					: false;
			}

			return true;
		}

		return false;
	}

	#[\ReturnTypeWillChange] // Suppress warning temporarily
	public function gc($maxlifetime): bool
	{
		if (!is_dir($this->_config['save_path']) OR ($directory = opendir($this->_config['save_path'])) === FALSE)
		{
			log_message('debug', "Session: Garbage collector couldn't list files under directory '".$this->_config['save_path']."'.");
			return false;
		}

		$ts = time() - $maxlifetime;

		$pattern = ($this->_config['match_ip'] === TRUE)
			? '[0-9a-f]{32}'
			: '';

		$pattern = sprintf(
			'#\A%s'.$pattern.$this->_sid_regexp.'\z#',
			preg_quote($this->_config['cookie_name'])
		);

		$deleted = 0;
		while (($file = readdir($directory)) !== FALSE)
		{
			if (preg_match($pattern, $file) === 1 && (filemtime($this->_config['save_path'].'/'.$file) < $ts))
			{
				if (unlink($this->_config['save_path'].'/'.$file))
				{
					$deleted++;
				}
			}
		}

		closedir($directory);
		return $deleted > 0;
	}

// Other parts of the CI_Session_files_driver class remain unchanged...

public function validateId($id): bool // Change visibility to public
{
    return (bool) preg_match('#\A'.$this->_sid_regexp.'\z#', $id);
}

// Other parts of the CI_Session_files_driver class remain unchanged...

	public function php5_validate_id()
	{
		if (PHP_VERSION_ID < 70000 && isset($_COOKIE[$this->_config['cookie_name']])
			&& ! $this->validateId($_COOKIE[$this->_config['cookie_name']]))
		{
			unset($_COOKIE[$this->_config['cookie_name']]);
		}
	}
}
