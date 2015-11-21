<?php
session_start();
//ini_set('display_errors', 'On');
header('Content-Type: text/plain');

//we need to create this file
//  and never ever commit it to the git rep   use .gitignore
include "storedInfo.php"; //contains hostname/username/password/databasename

//$minPassLength = 7;


//check that user and pass provided
if (!isset($_POST['request']) || !isset($_POST['username']) || !isset($_POST['password']) 
    || !$_POST['request']) || !$_POST['username'] || !$_POST['password']){

    http_response_code(400); //bad request
    echo "Username and password must be provided";
    exit();

}

//connect to database with created mysqli object
$mysqli = new mysqli($hostname, $Username, $Password, $DatabaseName);
if ($mysqli->connect_errno || $mysqli->connect_error)
{
    http_response_code(500);
    echo "User Login currently unvailable";
    exit();
}

//name of table in databaseZ
$userTable = "usertable";

//create table if it doesnt exist

//we need to set up our table here
$mysqli->query("CREATE TABLE IF NOT EXISTS $userTable (
    
)");


//check if username exists
$usrInStmt = $mysqli->prepare("SELECT COUNT(*) FROM usertable WHERE name = ?");
$usrInStmt->bind_param("s", $_POST['username']);
$usrInStmt->execute();
$usrInStmt->bind_result($userExists);
$usrInStmt->fetch();
$usrInStmt->close();


if($_POST['request'] == 'login'){
    //check that user is in database
    if(!$userExists){
        http_response_code(404);
        echo "We dont have a user with that name. Would you like to create that account now?";
        exit();
    }
    //check that password matches what we have in database
    //retrieve has from database
    $getHash = $mysqli->prepare("SELECT passHashed FROM $userTable WHERE name = ?");
    $getHash->bind_param("s",$_POST['username']);
    $getHash->execute();
    $getHash->bind_result($hash);
    $getHash->fetch();
    $getHash->close();
    //PLEASE NOTE: the database stored string includes algo, random salt, and hash
    if(password_verify($_POST['password'],$hash)){
        http_response_code(200);
        if(session_status() == PHP_SESSION_ACTIVE){
            $_SESSION['username'] = $username;
        }
        exit();
    } else {
        http_response_code(403);
        echo "Incorect Password";
        exit();
    }
} else if ($_POST['request'] == 'signup'){
    if($userExists) {
        http_response_code(409);
        echo "A user with that name already exists";
        exit();
    }

    //do we want min pass length,  if used uncommnet global variable up above
/*    if(strlen($_POST['password']) < $minPassLength) {
        http_response_code(406);
        echo "Password must be at least $minPassLength long";
        exit();
    }*/

    //PLEASE NOTE: the returned string includes algo, random salt, and hash
    $hashp = password_hash($_POST['password'], PASSWORD_DEFAULT);
    //add user to database
    $addUser = $mysqli->prepare("INSERT INTO 
        $userTable ( name, passHashed) 
        VALUES (?,?)");
    $addUser->bind_param("ssss", $_POST['username'], $hashp);
    if(!$addUser->execute()){
        http_response_code(500);
        echo "We cannot perform that action right now";
        exit();
    }
    $addUser->close();
    
    http_response_code(201);
    if(session_status() == PHP_SESSION_ACTIVE){
        $_SESSION['username'] = $username;
    }
    exit();

} else {
    http_response_code(500);
    echo "We cannot perform that action right now";
    exit();
}
?>