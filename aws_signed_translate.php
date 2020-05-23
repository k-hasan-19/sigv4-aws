<?php
require __DIR__.'/../vendor/autoload.php';


# ************* REQUEST VALUES *************
$method = "POST";
$service = "translate";
$region = "us-west-2";
$host = $service . "." . $region . ".amazonaws.com";
$endpoint = "https://" . $host . "/";

# POST requests use a content type header. For Amazon Translate,
# the content is JSON.
$content_type = "application/x-amz-json-1.1";
# Amazon Translate requires an x-amz-target header that has this format:
#     AWSShineFrontendService_20170701.<operationName>.
$amz_target = "AWSShineFrontendService_20170701.TranslateText";

# Pass request parameters for the TranslateText operation in a JSON block.
$request_parameters = "{";
$request_parameters .= '"Text": "Hello world.",';
$request_parameters .= '"SourceLanguageCode": "en",';
$request_parameters .= '"TargetLanguageCode": "de"';
$request_parameters .= "}";

# The following functions derive keys for the request. For more information, see
# http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python.
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



# Python can read the AWS access key from environment variables or the configuration file.
# In this example, keys are stored in environment variables. As a best practice, do not
# embed credentials in code.
$access_key = getenv('AWS_ACCESS_KEY_ID');
$secret_key = getenv('AWS_SECRET_ACCESS_KEY');


# Create a date for headers and the credential string
$t = new DateTime('UTC');
$amz_date = $t->format('Ymd\THis\Z'); //t.strftime("%Y%m%dT%H%M%SZ")
$date_stamp = $t->format('Ymd'); //t.strftime("%Y%m%d")  # Date w/o time, used in credential scope


# ************* TASK 1: CREATE A CANONICAL REQUEST *************
# For information about creating a canonical request, see http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html.

# Step 1: Define the verb (GET, POST, etc.), which you have already done.

# Step 2: Create a canonical URI. A canonical URI is the part of the URI from domain to query.
# string (use '/' if no path)
$canonical_uri = "/";

## Step 3: Create the canonical query string. In this example, request
# parameters are passed in the body of the request and the query string
# is blank.
$canonical_querystring = "";

# Step 4: Create the canonical headers. Header names must be trimmed,
# lowercase, and sorted in code point order from low to high.
# Note the trailing \n.
$canonical_headers = 
    "content-type:"
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
    . "\n"
;


# Step 5: Create the list of signed headers by listing the headers
# in the canonical_headers list, delimited with ";" and in alphabetical order.
# Note: The request can include any headers. Canonical_headers and
# signed_headers should contain headers to include in the hash of the
# request. "Host" and "x-amz-date" headers are always required.
# For Amazon Translate, content-type and x-amz-target are also required.
$signed_headers = "content-type;host;x-amz-date;x-amz-target";

# Step 6: Create the payload hash. In this example, the request_parameters
# variable contains the JSON request parameters.
// payload_hash = hashlib.sha256(request_parameters.encode()).hexdigest()
$payload_hash = hash('sha256', utf8_encode($request_parameters));
# Step 7: Combine the elements to create a canonical request.
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


# ************* TASK 2: CREATE THE STRING TO SIGN*************
# Set the algorithm variable to match the hashing algorithm that you use, either SHA-256 (recommended) or SHA-1.
#
$algorithm = "AWS4-HMAC-SHA256";
$credential_scope = $date_stamp . "/" . $region . "/" . $service . "/" . "aws4_request";
$string_to_sign = 
    $algorithm
    . "\n"
    . $amz_date
    . "\n"
    . $credential_scope
    . "\n"
    . hash('sha256', utf8_encode($canonical_request));


# ************* TASK 3: CALCULATE THE SIGNATURE *************
# Create the signing key using the getSignaturKey function defined above.
$signing_key = getSignatureKey($secret_key, $date_stamp, $region, $service);

# Sign the string_to_sign using the signing_key.

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

# For Amazon Translate, the request can include any headers, but it must include "host," "x-amz-date,"
# "x-amz-target," "content-type," and "Authorization" headers. Except for the authorization
# header, the headers must be included in the canonical_headers and signed_headers values, as
# noted earlier. Header order is not significant.
# Note: The Python 'requests' library automatically adds the 'host' header.
$headers = array(
    "Content-Type"=> $content_type,
    "X-Amz-Date"=> $amz_date,
    "X-Amz-Target"=> $amz_target,
    "Authorization"=> $authorization_header,
);

// print_r($headers);
// exit;
use GuzzleHttp\Client as GuzzleClient;

$client = new GuzzleClient([
    'headers' => $headers
]);


$body = $request_parameters;

$r = $client->request('POST', $endpoint, [
    'body' => $request_parameters
]);
$response = $r->getBody()->getContents();

echo $response;
