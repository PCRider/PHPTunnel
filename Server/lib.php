<?php
#lib
error_reporting( E_ALL );
require_once('cfg.php');
include(dirname(__FILE__)."/phpcrypt/phpCrypt.php");
use PHP_Crypt\PHP_Crypt as PHP_Crypt;

function RFC1123Date(){
   return gmdate('D, d M Y H:i:s T', time()); 
}  

function LogLine($ll,$msg, $dest="./log",$lname="log",$lsize=10000) {
	# Is the log directory writable?
        if(!file_exists ( $dest )){
            mkdir ( $dest , 0777  );
        }
//    if ( !$CONFIG['enable_logging'] &&  $CONFIG['log_level'] < $ll ) {
//        return
//    }
		# Filename to save as
		$file = $dest . '/' . $lname ."-". date('Y-m-d') . '.log';
        
        
        if(!file_exists ( $file )){
            touch( $file );
            
        }
        # i could do it with fstat($filehandle)["size"] but this is a cleanner way when i am using file_put_contents()
        else if (filesize($file) > $lsize) {
            # i could use date("d.m.Y H:i:s")
            file_put_contents ($file, RFC1123Date() ." - Logfile reached maximum size ($lsize)- rotating.\r\n", FILE_APPEND);
	        rename ($file,"$file.old");
	        file_put_contents($file, RFC1123Date() ." - Opening new Logfile.\r\n", FILE_APPEND);
        }
        
		# Line to write
		$towrite = str_pad($_SERVER['REMOTE_ADDR'] . ', ' , 17) . RFC1123Date() . ', ' . $_SERVER['PHP_SELF'] ."\r\n". $msg . "\r\n";

		# Do it (I could do it in a nasty way fopen() fwrite() fclose())
		file_put_contents($file, $towrite, FILE_APPEND);
}



/**
 * Open mcrypt ARC4 Module In Stream Mode and Initialize with Key
 * @param str $key
 * @return encryption descriptor || false || void die()
 */
function OpenCryptModule($key){
    if(!is_null($key)){
		$td = new PHP_Crypt($key, PHP_Crypt::CIPHER_ARC4, PHP_Crypt::MODE_STREAM);
    }
	if(!is_resource($td))
	{
		header('HTTP/1.0 500 Internal Server Error');
		die();
	}
	// mcrypt_generic_init($td, $key, '');
	return $td;
}
/**
 * Open Read RAW Input or Write RAW Output and release the resource if fails
 * @param encryption descriptor $td, str $io $rw
 * @return pointer resource || false || void die()
 */
function OpenRawIO($td, $io, $rw, $socket=null){
	$IOHandle = fopen($io, $rw);
	if(!$IOHandle){
		if($socket){fclose($socket);}
		header('HTTP/1.0 500 Internal Server Error');
		die();
	}
	return $IOHandle;
}
/**
 * Reading HTTP Header from IO pointer resource with optinal dcryption
 * @param pointer resource $IOHandle, encryption descriptor $td, bool $decrypt
 * @return string || null 
 */
function HTTPHeaderReader($IOHandle,$td,$decrypt){
	$http_header = '';
	$http_header_length = 0;
	
	while(!feof($IOHandle))
	{
		$buffer = fread($IOHandle, 1);
		$buffer_length = strlen($buffer);
		
		if($buffer_length > 0)
		{
			# i am not sure how
			$http_header = $http_header . ($decrypt ?rc4($key, $buffer) : $buffer) ;
			$http_header_length = strlen($http_header);
			
			if($http_header_length >= 4)
			{
				if
				(
					$http_header[$http_header_length - 4] == "\r" && 
					$http_header[$http_header_length - 3] == "\n" && 
					$http_header[$http_header_length - 2] == "\r" && 
					$http_header[$http_header_length - 1] == "\n"
				)
				{
					break;
				}
			}
		}
	}
    return $http_header;
}
function OutputERR($msg,$td,$key){
    $time = gmdate('D, d M Y H:i:s T', time());
    $headermessage = "\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html;charset=utf8\r\n\r\n<html><head><title>PHPTunnel Error</title></head><body><h1>{$msg}</h1></body></html>";
	$rawOutputHandle = OpenRawIO($td, 'php://output', 'w');
    fwrite($rawOutputHandle, $crypt->encrypt($headermessage));
    fclose($rawOutputHandle);

    die();
}

function GetHeaderPartValue($http_header,$part){
	
	$http_header_lines = explode("\r\n", $http_header);
	$http_header_lines_count = count($http_header_lines);
	
	$http_address = '';
	$http_port = 0;
	#we begin with one because the 0th position is for request type(GET POST ...)
	$i = 1;
	# minus 2 because of first and last \r\n
	while($i < $http_header_lines_count - 2)
	{
		$http_header_line = $http_header_lines[$i];
		$http_header_line_array = explode(': ', $http_header_line);
		$http_header_line_array_count = count($http_header_line_array);
		if($http_header_line_array_count == 2)
		{
			$http_header_line_key = $http_header_line_array[0];
			$http_header_line_value = $http_header_line_array[1];
			$HTTPHeader[$http_header_line_key]=$http_header_line_value;
			if(strtoupper($http_header_line_key) == strtoupper($part))
			{
				//$return = $http_header_line_value;
				return $http_header_line_value;
				//break;
			}
		}
		$i = $i + 1;
		
	}
	//return $http_header_line_value;
}
function OpenSocket($http_header_value,$force,$IOHandle,$td){
//	$http_header_key = $http_header_key_value[0];
//	$http_header_value = $http_header_key_value[1];
	$http_header_host_parts = explode(':', $http_header_value);
	$http_header_host_parts_length = count($http_header_host_parts);
	if($http_header_host_parts_length == 1)
	{
		$http_address = $http_header_host_parts[0];
		$http_port = $force;
	}
	else
	{
		if($http_header_host_parts_length == 2)
		{
			$http_address = $http_header_host_parts[0];
			$http_port = $http_header_host_parts[1];
		}
	}
	if ($force == 80){
	    $SocketHandle = fsockopen($http_address, $http_port);
	}
	elseif($force == 443){
	     $SocketHandle = fsockopen('ssl://' . $http_address, $http_port);
	}
	if(!$SocketHandle){
		fclose($IOHandle);
		header('HTTP/1.0 500 Internal Server Error');
		die();
	}
	return $SocketHandle;
}
function TransferData($from,$to,$td,$type){
    while(!feof($from)){
			$buffer = fread($from, 5120);
			$buffer_length = strlen($buffer);
		if($buffer_length > 0){
		    if($type =="crypt"){
		        fwrite($to, $crypt->encrypt($buffer));
		    }
			else if($type =="decrypt"){
	        	fwrite($to,$crypt->decrypt($buffer));
	        }
		}
	}
}
function sendcutomheader(){
    for($i = 0; $i < count($RESPONSE_PROPERTY_KEY); $i = $i + 1)
		{
			if($RESPONSE_PROPERTY_KEY[$i] != '')
			{
				header($RESPONSE_PROPERTY_KEY[$i] . ': ' . $RESPONSE_PROPERTY_VALUE[$i]);
			}
		}
}
?>