<?php
// Database connection class
class Database {
    private $host = 'localhost';
    private $username = 'root';
    private $password = '';
    private $database = 'ecommerce';
    public $connection;

    public function __construct() {
        $this->connection = new mysqli($this->host, $this->username, $this->password, $this->database);
        if ($this->connection->connect_error) {
            die("Connection failed: " . $this->connection->connect_error);
        }
    }

    public function close() {
        $this->connection->close();
    }
}

// User class for handling authentication
class User {
    private $conn;

    public function __construct($connection) {
        $this->conn = $connection;
    }

    public function signUp($username, $password) {
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
        $stmt = $this->conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        $stmt->bind_param("ss", $username, $hashedPassword);
        $stmt->execute();
        $stmt->close();
        return "Sign-up successful! Please log in.";
    }

    public function login($username, $password) {
        $stmt = $this->conn->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            return true;
        }
        return false;
    }

    public function logout() {
        session_destroy();
    }
}

// Product class for managing products
class Product {
    private $conn;

    public function __construct($connection) {
        $this->conn = $connection;
    }

    public function add($product_name, $price) {
        $stmt = $this->conn->prepare("INSERT INTO products (product_name, price) VALUES (?, ?)");
        $stmt->bind_param("sd", $product_name, $price);
        $stmt->execute();
        $stmt->close();
    }

    public function edit($id, $product_name, $price) {
        $stmt = $this->conn->prepare("UPDATE products SET product_name = ?, price = ? WHERE id = ?");
        $stmt->bind_param("sdi", $product_name, $price, $id);
        $stmt->execute();
        $stmt->close();
    }

    public function delete($id) {
        $stmt = $this->conn->prepare("DELETE FROM products WHERE id = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        $stmt->close();
    }

    public function fetchAll() {
        return $this->conn->query("SELECT * FROM products");
    }

    public function fetchById($id) {
        $stmt = $this->conn->prepare("SELECT * FROM products WHERE id = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        return $stmt->get_result()->fetch_assoc();
    }
}

// Start session and instantiate classes
session_start();
$db = new Database();
$user = new User($db->connection);
$product = new Product($db->connection);
$message = '';

// Handle sign-up
if (isset($_POST['action']) && $_POST['action'] == 'signup') {
    $message = $user->signUp($_POST['username'], $_POST['password']);
}

// Handle login
if (isset($_POST['action']) && $_POST['action'] == 'login') {
    if (!$user->login($_POST['username'], $_POST['password'])) {
        $message = "Invalid username or password!";
    }
}

// Handle logout
if (isset($_GET['action']) && $_GET['action'] == 'logout') {
    $user->logout();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Handle product actions
if (isset($_SESSION['user_id']) && $_SERVER['REQUEST_METHOD'] == 'POST') {
    $action = $_POST['action'];
    $product_name = $_POST['product_name'] ?? '';
    $price = $_POST['price'] ?? 0;
    $id = $_POST['id'] ?? 0;

    if ($action == 'add') {
        $product->add($product_name, $price);
    } elseif ($action == 'edit') {
        $product->edit($id, $product_name, $price);
    } elseif ($action == 'delete') {
        $product->delete($id);
    }
}

// Fetch products
$products = $product->fetchAll();

// Handle product edit (pre-populate form)
$product_to_edit = null;
if (isset($_GET['action']) && $_GET['action'] == 'edit' && isset($_GET['id'])) {
    $id = $_GET['id'];
    $product_to_edit = $product->fetchById($id);
}

?>

