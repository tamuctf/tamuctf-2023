<?php
if(!isset($_COOKIE['auth_token']) || !is_admin($_COOKIE['auth_token'])) {
  header('Location: ?page=login');
  die();
}
?>

<?php include(INCLUDE_DIR . 'header.php'); ?>
<center>
  <h1><?php include('/flag.txt'); ?></h1>
</center>
<?php include(INCLUDE_DIR . 'footer.php'); ?>
