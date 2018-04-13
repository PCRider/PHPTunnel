<?php
#https
require_once('lib.php');
$key = $CONFIG['KEY'];
LogLine(2,"Key: {$CONFIG['KEY']}");
$td = OpenCryptModule($key);
LogLine(2,"Cript: $td ");
$inputHandle = OpenRawIO($td, 'php://input', 'r', null);
LogLine(2,"Input: $inputHandle");
$http_header = HTTPHeaderReader($inputHandle,$td,true);
LogLine(2,"Header: $http_header");
 
 $http_header_line_value=GetHeaderPartValue($http_header,"Host");
//$parsed_header = http_parse_headers ( $http_header );
//$http_header_line_value = $parsed_header['Host'];
//LogLine(2,"Header: print_r($parsed_header)");

$SocketHandle=OpenSocket($http_header_line_value,443,$inputHandle,$td);
LogLine(2,"Socket: $SocketHandle");
fwrite($SocketHandle, $http_header);
TransferData($inputHandle,$SocketHandle,$td,"decrypt");
LogLine(2,"data transfered: done");
fclose($inputHandle);
mcrypt_generic_deinit($td);
mcrypt_module_close($td);
$td = OpenCryptModule($key);
$outputHandle = OpenRawIO($td, 'php://output', 'w', $SocketHandle);
TransferData($SocketHandle,$outputHandle,$td,"crypt");

//OutputERR($http_header_line_value,$td,$key);
fclose($SocketHandle);
fclose($outputHandle);
mcrypt_generic_deinit($td);
mcrypt_module_close($td);
?>