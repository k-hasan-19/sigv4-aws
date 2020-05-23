<?php
require __DIR__.'/../vendor/autoload.php';

$method = "POST";
$service = "dynamodb";
$host = "dynamodb.us-west-2.amazonaws.com";
$region = "us-west-2";
$endpoint = "https://dynamodb.us-west-2.amazonaws.com/";
$content_type = "application/x-amz-json-1.0";
$amz_target = "DynamoDB_20120810.CreateTable";

# Request parameters for CreateTable--passed in a JSON block.
$request_parameters = "{";
$request_parameters .= '"KeySchema": [{"KeyType": "HASH","AttributeName": "Id"}],';
$request_parameters .= '"TableName": "TestTable","AttributeDefinitions": [{"AttributeName": "Id","AttributeType": "S"}],';
$request_parameters .= '"ProvisionedThroughput": {"WriteCapacityUnits": 5,"ReadCapacityUnits": 5}';

$request_parameters .= "}";

function sign($key, $msg){
    $msg_encoded = utf8_encode($msg);
    return hash_hmac('sha256', $msg_encoded, $key, true);
}

function getSignatureKey($key, $date_stamp, $regionName, $serviceName){
    $kDate = sign(utf8_encode("AWS4" . $key), $date_stamp);
    $kRegion = sign($kDate, $regionName);
    $kService = sign($kRegion, $serviceName);
    $kSigning = sign($kService, "aws4_request");
    return $kSigning;
}

$access_key = getenv('AWS_ACCESS_KEY_ID');
$secret_key = getenv('AWS_SECRET_ACCESS_KEY');

# Create a date for headers and the credential string
$t = new DateTime('UTC');
$amz_date = $t->format('Ymd\THis\Z'); //t.strftime("%Y%m%dT%H%M%SZ")
$date_stamp = $t->format('Ymd'); //t.strftime("%Y%m%d")  # Date w/o time, used in credential scope

// ************* TASK 1: CREATE A CANONICAL REQUEST *************
// http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

// Step 1 is to define the verb (GET, POST, etc.)--already done.

// Step 2: Create canonical URI--the part of the URI from domain to query
// string (use '/' if no path)
$canonical_uri = "/";

// # Step 3: Create the canonical query string. In this example, request
// parameters are passed in the body of the request and the query string
// is blank.
$canonical_querystring = "";

// Step 4: Create the canonical headers. Header names must be trimmed
// and lowercase, and sorted in code point order from low to high.
// Note that there is a trailing \n.
$canonical_headers = "content-type:"
    . $content_type
    . "\n"
    . "host:"
    . $host
    . "\n"
    . "x-amz-date:"
    . $amz_date
    . "\n"
    . "x-amz-target:"
    . $amz_target
    . "\n";

// echo $canonical_headers;
// exit;


// Step 5: Create the list of signed headers. This lists the headers
// in the canonical_headers list, delimited with ";" and in alpha order.
// Note: The request can include any headers; canonical_headers and
// signed_headers include those that you want to be included in the
// hash of the request. "Host" and "x-amz-date" are always required.
// For DynamoDB, content-type and x-amz-target are also required.
$signed_headers = "content-type;host;x-amz-date;x-amz-target";

# Step 6: Create payload hash. In this example, the payload (body of
# the request) contains the request parameters.
// payload_hash = hashlib.sha256(request_parameters.encode("utf-8")).hexdigest()

$payload_hash = hash('sha256', utf8_encode($request_parameters));
# Step 7: Combine elements to create canonical request
$canonical_request = 
    $method
    . "\n"
    . $canonical_uri
    . "\n"
    . $canonical_querystring
    . "\n"
    . $canonical_headers
    . "\n"
    . $signed_headers
    . "\n"
    . $payload_hash;
// echo $canonical_request;
// exit;
    
# ************* TASK 2: CREATE THE STRING TO SIGN*************
# Match the algorithm to the hashing algorithm you use, either SHA-1 or
# SHA-256 (recommended)
$algorithm = "AWS4-HMAC-SHA256";
$credential_scope = $date_stamp . "/" . $region . "/" . $service . "/" . "aws4_request";
$string_to_sign = 
    $algorithm
    . "\n"
    . $amz_date
    . "\n"
    . $credential_scope
    . "\n"
    . hash('sha256', utf8_encode($canonical_request)); //hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()

// echo $string_to_sign;
// exit;
# ************* TASK 3: CALCULATE THE SIGNATURE *************
# Create the signing key using the function defined above.
$signing_key = getSignatureKey($secret_key, $date_stamp, $region, $service);

# Sign the string_to_sign using the signing_key
// signature = hmac.new(
//     signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256
// ).hexdigest()

$signature = hash_hmac('sha256', utf8_encode($string_to_sign), $signing_key);
# ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
# Put the signature information in a header named Authorization.
$authorization_header = 
    $algorithm
    . " "
    . "Credential="
    . $access_key
    . "/"
    . $credential_scope
    . ", "
    . "SignedHeaders="
    . $signed_headers
    . ", "
    . "Signature="
    . $signature;

// echo $authorization_header.'\n';
// exit;
# For DynamoDB, the request can include any headers, but MUST include "host", "x-amz-date",
# "x-amz-target", "content-type", and "Authorization". Except for the authorization
# header, the headers must be included in the canonical_headers and signed_headers values, as
# noted earlier. Order here is not significant.
# # Python note: The 'host' header is added automatically by the Python 'requests' library.
// headers = {
//     "Content-Type": content_type,
//     "X-Amz-Date": amz_date,
//     "X-Amz-Target": amz_target,
//     "Authorization": authorization_header,
// }

$headers = array(
"Content-Type"=> $content_type,
"X-Amz-Date"=> $amz_date,
"X-Amz-Target"=> $amz_target,
"Authorization"=> $authorization_header
    );
    
// print_r($headers);
// exit;
use GuzzleHttp\Client as GuzzleClient;


$client = new GuzzleClient([
    'headers' => $headers
]);

$body = $request_parameters;

$r = $client->request('POST', $endpoint, [
    'body' => $body
]);
$response = $r->getBody()->getContents();

echo $response;
