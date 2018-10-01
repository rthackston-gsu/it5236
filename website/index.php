<?php
	
// Import the application classes
require_once('include/classes.php');

// Create an instance of the Application class
$app = new Application();
$app->setup();

// Declare an empty array of error messages
$errors = array();

?>

<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>Discussion</title>
	<meta name="description" content="Russell Thackston's personal website for IT 5236">
	<meta name="author" content="Russell Thackston">
	<link rel="stylesheet" href="css/style.css">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
	<?php include 'include/header.php'; ?>
	<h2>Mobile Web Infrastructure</h2>
	<p>
		This is a bare-bones "list-oriented" web application for use in IT 5236, to teach mobile web infrastructure concepts.
		Students currently registered for the course may <a href="login.php">create an account</a> or proceed directly to the 
		<a href="login.php">login page</a>.
	</p>
	<?php include 'include/footer.php'; ?>
	<script src="js/site.js"></script>
</body>
</html>
