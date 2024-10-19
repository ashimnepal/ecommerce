<?php
// dbinit.php
$servername = "localhost";
$username = "root";  // Your DB username
$password = "";      // Your DB password
$dbname = "ecommerce_db";  // Your DB name

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
