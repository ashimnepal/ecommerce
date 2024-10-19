<?php
include 'dbinit.php';

$action = $_POST['action'] ?? $_GET['action'];

if ($action == 'add') {
    $product_name = $_POST['product_name'];
    $price = $_POST['price'];

    $stmt = $conn->prepare("INSERT INTO products (product_name, price) VALUES (?, ?)");
    $stmt->bind_param("sd", $product_name, $price);

    if ($stmt->execute()) {
        header('Location: product_list.php');
    } else {
        echo "Error: " . $stmt->error;
    }
    $stmt->close();

} elseif ($action == 'edit') {
    $id = $_POST['id'];
    $product_name = $_POST['product_name'];
    $price = $_POST['price'];

    $stmt = $conn->prepare("UPDATE products SET product_name = ?, price = ? WHERE id = ?");
    $stmt->bind_param("sdi", $product_name, $price, $id);

    if ($stmt->execute()) {
        header('Location: product_list.php');
    } else {
        echo "Error: " . $stmt->error;
    }
    $stmt->close();

} elseif ($action == 'delete') {
    $id = $_GET['id'];

    $stmt = $conn->prepare("DELETE FROM products WHERE id = ?");
    $stmt->bind_param("i", $id);

    if ($stmt->execute()) {
        header('Location: product_list.php');
    } else {
        echo "Error: " . $stmt->error;
    }
    $stmt->close();
}

$conn->close();
?>
