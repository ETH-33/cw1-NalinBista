<?php
    require 'Connection.php';

    $ActionType = isset($_GET['ActionType']) ? $_GET['ActionType'] : '';
    $Username = isset($_POST['Username']) ? $_POST['Username'] : '';
    $Password = isset($_POST['Password']) ? $_POST['Password'] : '';
    $Firstname = isset($_POST['Firstname']) ? $_POST['Firstname'] : '';
    $Middlename = isset($_POST['Middlename']) ? $_POST['Middlename'] : '';
    $Lastname = isset($_POST['Lastname']) ? $_POST['Lastname'] : '';
    $Address = isset($_POST['Address']) ? $_POST['Address'] : '';
    $EmailAddress = isset($_POST['EmailAddress']) ? $_POST['EmailAddress'] : '';

    // Validation
    $isValid = true;
    $errors = array();

    if (empty($Username) || empty($Password) || empty($Firstname) || empty($Middlename) || empty($Lastname) || empty($Address) || empty($EmailAddress)) {
        $errors[] = "Cannot leave the page blank";
        $isValid = false;
    }

    if (strlen($Username) < 6) {
        $errors[] = "Username should be at least 6 characters long.";
        $isValid = false;
    }

    if (strlen($Password) < 8 || !preg_match('/[!@#$%^&*()\-_=+{};:,<.>]/', $Password)) {
        $errors[] = "Password should be at least 8 characters long and contain a special character.";
        $isValid = false;
    }

    if (!filter_var($EmailAddress, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email address.";
        $isValid = false;
    }

    if (!$isValid) {
        foreach ($errors as $error) {
            echo '<script>window.alert("' . $error . '");</script>';
        }
    } else {
        // Check if the email address is already registered
        $stmt = mysqli_prepare($Conn, "SELECT COUNT(*) FROM `tbl_customers` WHERE `EmailAddress` = ?");
        mysqli_stmt_bind_param($stmt, "s", $EmailAddress);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_bind_result($stmt, $emailCount);
        mysqli_stmt_fetch($stmt);
        mysqli_stmt_close($stmt);

        if ($emailCount > 0) {
            echo '<script>window.alert("This email address is already registered.");</script>';
        } else {
            // Generate a random salt
            $salt = bin2hex(random_bytes(16));

            // Combine the password and salt
            $passwordWithSalt = $Password . $salt;

            // Hash the password with the salt using bcrypt algorithm
            $hashedPassword = password_hash($passwordWithSalt, PASSWORD_BCRYPT);

            // Database operations with prepared statements
            if ($ActionType == "Register") {
                // Add the 'Salt' column to the table if not already added
                $alterTableQuery = "ALTER TABLE `tbl_customers` ADD `Salt` VARCHAR(64) NOT NULL";
                mysqli_query($Conn, $alterTableQuery);

                $stmt = mysqli_prepare($Conn, "INSERT INTO `tbl_customers`(`Username`, `Password`, `Salt`, `Role`, `Firstname`, `Middlename`, `Lastname`, `Address`, `EmailAddress`) VALUES (?, ?, ?, 'User', ?, ?, ?, ?, ?)");
                mysqli_stmt_bind_param($stmt, "ssssssss", $Username, $hashedPassword, $salt, $Firstname, $Middlename, $Lastname, $Address, $EmailAddress);
                $res = mysqli_stmt_execute($stmt);

                if (!$res) {
                    echo "Failed " . mysqli_error($Conn);
                } else {
                    echo '<script>window.alert("Registration Completed! Please Login"); window.open("Login.php?Role=User","_self",null,true);</script>';
                }

                mysqli_stmt_close($stmt);
            } else {
                $ID = isset($_GET['ID']) ? $_GET['ID'] : '';
                $stmt = mysqli_prepare($Conn, "UPDATE `tbl_customers` SET `Username`=?, `Password`=?, `Salt`=?, `Firstname`=?, `Middlename`=?, `Lastname`=?, `Address`=?, `EmailAddress`=? WHERE CustomerID = ?");
                mysqli_stmt_bind_param($stmt, "ssssssssi", $Username, $hashedPassword, $salt, $Firstname, $Middlename, $Lastname, $Address, $EmailAddress, $ID);
                $res = mysqli_stmt_execute($stmt);

                if (!$res) {
                    echo "Failed " . mysqli_error($Conn);
                } else {
                    if ($_GET['Loc'] == "MA") {
                        echo '<script>window.open("ManageAccount.php","_self",null,true);</script>';
                    } else if ($_GET['Loc'] == "MC") {
                        echo '<script>window.open("Management_Customers.php","_self",null,true);</script>';
                    }
                }

                mysqli_stmt_close($stmt);
            }
        }
    }
?>
