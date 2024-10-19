<?php
include 'dbinit.php';

$id = $_GET['id'];
$sql = "SELECT * FROM products WHERE id = $id";
$result = $conn->query($sql);
$product = $result->fetch_assoc();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit Product</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container">
        <h1 class="my-4">Edit Product</h1>
        <form action="selfprocessing.php" method="POST">
            <input type="hidden" name="action" value="edit">
            <input type="hidden" name="id" value="<?php echo $product['id']; ?>">

            <div class="mb-3">
                <label for="product_name" class="form-label">Product Name</label>
                <input type="text" id="product_name" name="product_name" class="form-control" value="<?php echo $product['product_name']; ?>" required>
            </div>

            <div class="mb-3">
                <label for="price" class="form-label">Price</label>
                <input type="number" id="price" name="price" class="form-control" value="<?php echo $product['price']; ?>" step="0.01" required>
            </div>

            <button type="submit" class="btn btn-primary">Update Product</button>
            <a href="product_list.php" class="btn btn-secondary">Back to List</a>
        </form>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
