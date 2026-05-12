<?php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Accept');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

$endpoint = getenv('SPARQL_ENDPOINT') ?: 'http://192.168.6.123:8890/sparql/';
$query    = file_get_contents('php://input');

if (empty(trim($query))) {
    http_response_code(400);
    echo json_encode(['error' => 'Empty query']);
    exit;
}

$ch = curl_init($endpoint);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST           => true,
    CURLOPT_POSTFIELDS     => $query,
    CURLOPT_HTTPHEADER     => [
        'Content-Type: application/sparql-query',
        'Accept: application/sparql-results+json',
    ],
    CURLOPT_TIMEOUT        => 30,
    CURLOPT_CONNECTTIMEOUT => 10,
]);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curlError = curl_error($ch);
curl_close($ch);

if ($curlError) {
    http_response_code(502);
    echo json_encode(['error' => 'Could not reach Virtuoso: ' . $curlError]);
    exit;
}

http_response_code($httpCode);
header('Content-Type: application/sparql-results+json');
echo $response;