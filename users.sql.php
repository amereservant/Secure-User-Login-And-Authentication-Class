<?php
/**
 * This is the database table structure SQL for the user class.
 *
 * version 1
 */

// Users Table Structure
$sql1 = "CREATE TABLE users (" .
        "id INTEGER PRIMARY KEY NOT NULL, ".
        "username VARCHAR(75) UNIQUE NOT NULL, ". // 75 chars to accomodate email if using email for login
        "password VARCHAR(40) NOT NULL, ".        // SHA1 Hash is always 40
        "pattern VARCHAR(22) NOT NULL, ".
        "salt1 VARCHAR(12) NOT NULL, ".
        "salt2 VARCHAR(10) NOT NULL )";
