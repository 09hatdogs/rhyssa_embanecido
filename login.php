<?php
// Start session
session_start();

// Database connection parameters
$servername = "localhost";
$username = "root"; // Default XAMPP username
$password = ""; // Default XAMPP password is empty
$dbname = "bound_treasures";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Process form data
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Validate input data
    $email = trim($_POST["email"]);
    $password = $_POST["password"];
    
    // Initialize errors array
    $errors = [];
    
    // Validate email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format";
    }
    
    // If no errors, check credentials
    if (empty($errors)) {
        // Prepare and bind
        $stmt = $conn->prepare("SELECT id, username, password_hash FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();
            
            // Verify password
            if (password_verify($password, $user['password_hash'])) {
                // Password is correct, start a new session
                session_start();
                
                // Store data in session variables
                $_SESSION['loggedin'] = true;
                $_SESSION['id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['email'] = $email;
                
                // Redirect to home page
                header("Location: index.html");
                exit;
            } else {
                // Password is incorrect
                $errors[] = "Incorrect email or password";
            }
        } else {
            // No user found with that email
            $errors[] = "Incorrect email or password";
        }
        
        $stmt->close();
    }
    
    // If there are errors, store them in session and redirect back to the login form
    if (!empty($errors)) {
        $_SESSION['login_errors'] = $errors;
        header("Location: login.html");
        exit;
    }
}

$conn->close();
?>