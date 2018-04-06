<?php
#http
require_once('lib.php');
//$key = "VAhUf2ZcvEmbtT1Y";
$key = $CONFIG['KEY'];
$td = OpenCryptModule($key);
$inputHandle = OpenRawIO($td, 'php://input', 'r', null);
$http_header = HTTPHeaderReader($inputHandle,$td,true);

OutputERR($http_header,$td,$key);

fclose($inputHandle);
mcrypt_generic_deinit($td);
mcrypt_module_close($td);
?>