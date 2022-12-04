<?php

// By : Hounaar
// I suggest us store procedure mostly with the method #2

// In these methods you can choose some of them. Hoever of course it is better to use all of these tactis

// Methods : 

// Methods #1 : You can use PDO connection rather than mysqli 



// PDO Connection VS Mysqli connection


	$servername = "localhost";
	$username = "";
	$password = "";

	try {
 		 $connection = new PDO('mysql:host="";dbname=""', "$username", $password);
  		// set the PDO error mode to exception
 		 $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
 		 echo "Connected successfully";
		} catch(PDOException $e) {
 			 echo "Connection failed: " . $e->getMessage();
		}

		}



/* Methods #2 :
WE CAN USE THE FUNCTION BELOW IN ORDER TO PREVENT ESCAPE FOR SQL INJECTION:
*/

$id = mysqli_real_escape_string($connection,$_POST['id']);
$password = mysqli_real_escape_string($connection,$_POST['password']);

/*
WE CAN SET SOME RGEX AND SET THE VARIABLES TO FOLLOW THE RGEX ORDERS. EITHER WAY WE GET A FILE LIKE THE RGEX FORMAT FROM JASON AD DECODE IT
AFTER THAT SET THE VARIBALE TO FOLLOW THE RGEX TRAILS.
WE CAN SET THE RGEX LIKE THIS:
*/

$website_rgex = "/\b(?:(?:https?|ftp):\/\/|www\.)[-a-z0-9+&@#\/%?=~_|!:,.;]*[-a-z0-9+&@#\/%=~_|]/i";
$id_rgex = "/^[a-zA-Z-0-9']*$/"'
$password_rgex = ""^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$""; // Minimum eight characters, at least one letter, one number and one special character:
$email //We can use FILTER_VALIDATE_EMAIL method for email validation.

if(!preg_match($id_rgex,id) or !preg_match($password_rgex,$password) or !filter_var($email,FILTER_VALIDATE_EMAIL)){
	echo "Your information needs to follow and specific instructions";
} else {
	echo " All inputs are valid";
}


/* Methods #4 :
We can use store procedrures in order to do the query. However it will reduce and prevent SQL Injection 
We can use store procedures like the ways below because unlike SQLServer defining store procedures is a bit diffrent in PHP
*/


$connection->query("Set @P0 = '$username'");
$connection->query("Set @P1 = '$email'");
$connection->query("Set @P2 = '$password'");
$connection->query("CALL $procedure_name(@P0,P1,P2)");


/* Method #5:
Follow the specific Database escaping.
*/ 

/*
Method #6:

A somewhat special case of escaping is that the method of hex-encode the complete string received from 
the user (this may be seen as escaping each character). the online application ought to hex-encode the user input before as well as it within the SQL statement.
The SQL statement should take into consideration this fact, and consequently compare the informatio

*/

$connection->query("SELECT ... FROM session WHERE hex_encode(sessionID) = '616263313233' ... WHERE hex_encode ( ... ) = '2720 ... '");


/* Method #7:
Use canned expressions and parameter queries. These are SQL statements that are sent to  
the database server and analyzed separately from the parameters. This prevents an attacker from injecting malicious SQL.
*/

// UsingPDO
$stmt = $pdo->prepare('SELECT * FROM employees WHERE name = :name');
$stmt->execute(array('name' => $name));
foreach ($stmt as $row) {
    // do something with $row
}

// Mysqli
$stmt = $dbConnection->prepare('SELECT * FROM employees WHERE name = ?');
$stmt->bind_param('s', $name);
$stmt->execute();
$result = $stmt->get_result();
while ($row = $result->fetch_assoc()) {
    // do something with $row
}






?>