<?php
#lib
error_reporting( E_ALL );
require_once('cfg.php');

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
	    $td = mcrypt_module_open(MCRYPT_ARCFOUR, '', MCRYPT_MODE_STREAM, '');
    }
	if(!is_resource($td))
	{
		header('HTTP/1.0 500 Internal Server Error');
		die();
	}
	mcrypt_generic_init($td, $key, '');
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
		mcrypt_generic_deinit($td);
		mcrypt_module_close($td);
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
			$http_header = $http_header . ($decrypt ? mdecrypt_generic($td, $buffer) : $buffer) ;
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
    mcrypt_generic_init($td, $key, '');	
	$rawOutputHandle = OpenRawIO($td, 'php://output', 'w');
    fwrite($rawOutputHandle, mcrypt_generic($td, $headermessage));
    fclose($rawOutputHandle);
    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);
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
		mcrypt_generic_deinit($td);
		mcrypt_module_close($td);
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
		        fwrite($to, mcrypt_generic($td, $buffer));
		    }
			else if($type =="decrypt"){
	        	fwrite($to, mdecrypt_generic($td, $buffer));
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
/*
 * Copyright 2011 Michael Cutler <m@cotdp.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
  /**
   * A PHP implementation of RC4 based on the original C code from
   * the 1994 usenet post:
   *
   * http://groups.google.com/groups?selm=sternCvKL4B.Hyy@netcom.com
   *
   * @param key_str the key as a binary string
   * @param data_str the data to decrypt/encrypt as a binary string
   * @return the result of the RC4 as a binary string
   * @author Michael Cutler <m@cotdp.com>
   */
   function rc4( $key_str, $data_str ) {
      // convert input string(s) to array(s)
      $key = array();
      $data = array();
      for ( $i = 0; $i < strlen($key_str); $i++ ) {
         $key[] = ord($key_str{$i});
      }
      for ( $i = 0; $i < strlen($data_str); $i++ ) {
         $data[] = ord($data_str{$i});
      }
     // prepare key
      $state = array( 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
                      16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,
                      32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,
                      48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,
                      64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,
                      80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,
                      96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,
                      112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,
                      128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,
                      144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,
                      160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,
                      176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,
                      192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,
                      208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,
                      224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,
                      240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255 );
      $len = count($key);
      $index1 = $index2 = 0;
      for( $counter = 0; $counter < 256; $counter++ ){
         $index2   = ( $key[$index1] + $state[$counter] + $index2 ) % 256;
         $tmp = $state[$counter];
         $state[$counter] = $state[$index2];
         $state[$index2] = $tmp;
         $index1 = ($index1 + 1) % $len;
      }
      // rc4
      $len = count($data);
      $x = $y = 0;
      for ($counter = 0; $counter < $len; $counter++) {
         $x = ($x + 1) % 256;
         $y = ($state[$x] + $y) % 256;
         $tmp = $state[$x];
         $state[$x] = $state[$y];
         $state[$y] = $tmp;
         $data[$counter] ^= $state[($state[$x] + $state[$y]) % 256];
      }
      // convert output back to a string
      $data_str = "";
      for ( $i = 0; $i < $len; $i++ ) {
         $data_str .= chr($data[$i]);
      }
      return $data_str;
   }
?>