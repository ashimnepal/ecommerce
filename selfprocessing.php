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

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Product Management</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container">
        <h1 class="my-4">Product Management</h1>

        <!-- Authentication Section -->
        <?php if (!isset($_SESSION['user_id'])): ?>
            <div class="alert alert-info"><?php echo $message; ?></div>

            <!-- Sign-up Form -->
            <form action="" method="POST" class="mb-4">
                <input type="hidden" name="action" value="signup">
                <h3>Sign-up</h3>
                <div class="mb-3">
                    <label for="signup_username" class="form-label">Username</label>
                    <input type="text" id="signup_username" name="username" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label for="signup_password" class="form-label">Password</label>
                    <input type="password" id="signup_password" name="password" class="form-control" required>
                </div>
                <button type="submit" class="btn btn-primary">Sign up</button>
            </form>

            <!-- Login Form -->
            <form action="" method="POST">
                <input type="hidden" name="action" value="login">
                <h3>Login</h3>
                <div class="mb-3">
                    <label for="login_username" class="form-label">Username</label>
                    <input type="text" id="login_username" name="username" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label for="login_password" class="form-label">Password</label>
                    <input type="password" id="login_password" name="password" class="form-control" required>
                </div>
                <button type="submit" class="btn btn-success">Login</button>
            </form>

        
    </div>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.6/dist/umd/popper.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.min.js"></script>
</body>
</html>

<?php
// Close database connection
$db->close();
?>
