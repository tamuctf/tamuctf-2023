<!DOCTYPE html>
<html>
<head>
  <link rel="stylesheet" href="static/header.css">
  <link rel="stylesheet" href="static/<?php echo $resource; ?>.css">
  <title><?php echo APP_NAME; ?></title>
</head>
<body>
  <header>
    <div class="site-header">
      <div class="header-content">
        <a class="site-title" rel="author" href="?page=home">Home</a>
        <nav class="site-nav">
        <a class="page-link" href="?page=login">
<?php
if(isset($_COOKIE['auth_token']) && is_admin($_COOKIE['auth_token'])) {
  echo "Admin";
} else {
  echo "Login";
}
?>
        </a>
        </nav>
      </div>
    </div>
  </header>
