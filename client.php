<?php
namespace AEMCsApiClientLibPHP;
require_once 'IMSJWTTokenExchange.class.php';

// Generate Token
// Include required dependencies
use \IMSJWTTokenExchange;
use \Exception;

try {
  if(!isset($argv[1])){
    throw new Exception("Please!, add certificate Json");
  }

  $jsonFileName = $argv[1]; 
  $jsonFile = file_get_contents($jsonFileName); 

  // Check if the file was read successfully
  if ($jsonFile === false) {
    throw new Exception("Error!, not reading the JSON file");
  }  

  // Decode the JSON file
  $json_data = json_decode($jsonFile, true); 

  // Check if the JSON was decoded successfully
  if ($json_data === null) {
    throw new Exception("Error!, not decoding the JSON file");  
  }

  $token = exchangeToken($json_data);

  print_r($token);

} catch (\Throwable $th) {
  print_r($th);
}

