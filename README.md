# Sql_Injection_Prevention
This document is including some ways to prevent SQL Injection in PHP using some methods and tactics.

## Overview
A SQL injection assault comprises of inclusion or “injection” of a SQL inquiry through the input information from the client to the application. A fruitful SQL infusion abuse can examine delicate information from the database, adjust database information (Insert/Update/Delete), execute organization operations on the database (such as shutdown the DBMS), recoup the substance of a given record show on the DBMS record framework and in a few cases issue commands to the working framework. SQL infusion assaults are a sort of infusion assault, in which SQL commands are infused into data-plane input in arrange to influence the execution of predefined SQL commands.

### Threat
<ul>
  <li>
      SQL injection attacks allow attackers to impersonate, manipulate existing data, cause denial issues such as invalidating transactions or changing balances, allowing full disclosure of all data on the system, and destroying data. Or you can destroy otherwise inaccessible data and become the administrator of the database server.
  </li>
  <li>
    SQL Injection is extremely common with PHP and ASP applications thanks to the prevalence of older practical interfaces. thanks to the character of programmatic interfaces available, J2EE and ASP.NET applications are less probably to own simply exploited SQL injections.
The severity of SQL Injection attacks is restricted by the attacker’s talent and imagination, and to a lesser extent, defense thorough countermeasures, reminiscent of low privilege connections to the information server so on. In general, take into account SQL Injection a high impact severity.
  </li>
  </ul>
  
  ### Methods
  <ul>
  <li>
You can use PDO connection rather than mysqli 
PDO Connection VS Mysqli connection
</li>

  ```php
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

```

<li>
WE CAN USE THE FUNCTION BELOW IN ORDER TO PREVENT ESCAPE FOR SQL INJECTION:
</li>

```php
$id = mysqli_real_escape_string($connection,$_POST['id']);
$password = mysqli_real_escape_string($connection,$_POST['password']);
```

<li>

WE CAN SET SOME RGEX AND SET THE VARIABLES TO FOLLOW THE RGEX ORDERS. EITHER WAY WE GET A FILE LIKE THE RGEX FORMAT FROM JASON AD DECODE IT
AFTER THAT SET THE VARIBALE TO FOLLOW THE RGEX TRAILS.
WE CAN SET THE RGEX LIKE THIS:
</li>

```php
$website_rgex = "/\b(?:(?:https?|ftp):\/\/|www\.)[-a-z0-9+&@#\/%?=~_|!:,.;]*[-a-z0-9+&@#\/%=~_|]/i";
$id_rgex = "/^[a-zA-Z-0-9']*$/"'
$password_rgex = ""^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$""; // Minimum eight characters, at least one letter, one number and one special character:
$email //We can use FILTER_VALIDATE_EMAIL method for email validation.

if(!preg_match($id_rgex,id) or !preg_match($password_rgex,$password) or !filter_var($email,FILTER_VALIDATE_EMAIL)){
	echo "Your information needs to follow and specific instructions";
} else {
	echo " All inputs are valid";
}

```


<li>
We can use store procedrures in order to do the query. However it will reduce and prevent SQL Injection 
We can use store procedures like the ways below because unlike SQLServer defining store procedures is a bit diffrent in PHP
</li>

```php
$connection->query("Set @P0 = '$username'");
$connection->query("Set @P1 = '$email'");
$connection->query("Set @P2 = '$password'");
$connection->query("CALL $procedure_name(@P0,P1,P2)");
```

<li>Follow the specific Database escaping.</li>

<li>
A somewhat special case of escaping is that the method of hex-encode the complete string received from 
the user (this may be seen as escaping each character). the online application ought to hex-encode the user input before as well as it within the SQL statement.
The SQL statement should take into consideration this fact, and consequently compare the informatio
</li>

```php
$connection->query("SELECT ... FROM session WHERE hex_encode(sessionID) = '616263313233' ... WHERE hex_encode ( ... ) = '2720 ... '");
```


<li>
Use canned expressions and parameter queries. These are SQL statements that are sent to  
the database server and analyzed separately from the parameters. This prevents an attacker from injecting malicious 
</li>

```php

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

```

<li>
Try not to use <b> $_GET['']</b> method that much because it is actually vulnerable unless you are compelled to.
</li>

### THERE IS ANOTHER VULNERABLITY WHICH YOU CA USE AND READ IN MY GITHUB REPO. THE LINK IS BELOW
https://github.com/hounaar/magic_Hash

I hope you have enjoyed it
