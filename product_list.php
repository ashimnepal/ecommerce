<?php
include 'dbinit.php';

// Fetch products from the database
$sql = "SELECT * FROM products";
$result = $conn->query($sql);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Product List</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container">
        <h1 class="my-4">Product List</h1>
        <a href="add_product.php" class="btn btn-primary mb-4">Add New Product</a>
        <table class="table table-bordered">
            <thead class="thead-dark">
                <tr>
                    <th>ID</th>
                    <th>Product Name</th>
                    <th>Price</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
            <?php
            if ($result->num_rows > 0) {
                while($row = $result->fetch_assoc()) {
                    echo "<tr>
                            <td>{$row['id']}</td>
                            <td>{$row['product_name']}</td>
                            <td>{$row['price']}</td>
                            <td>
                                <a href='edit_product.php?id={$row['id']}' class='btn btn-warning btn-sm'>Edit</a>
                                <a href='selfprocessing.php?action=delete&id={$row['id']}' class='btn btn-danger btn-sm'>Delete</a>
                            </td>
                        </tr>";
                }
            } else {
                echo "<tr><td colspan='4'>No products found</td></tr>";
            }
            ?>
            </tbody>
        </table>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
