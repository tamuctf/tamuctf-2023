<?php
if(!isset($_COOKIE['auth_token'])) {
  setcookie('auth_token', generate_guest_token(), time() + (86400*30), '/');
} else if(is_admin($_COOKIE['auth_token'])) {
  header('Location: ?page=admin');
  die();
}

if(isset($_POST['username']) && isset($_POST['password'])) {
  $result = try_auth($_POST['username'], $_POST['password']); 
  if($result != false) {
    setcookie('auth_token', generate_admin_token($_POST['username'], end($result)), time() + (86400*30), '/');
    header('Location: ?page=admin');
    die();
  }
}
?>

<?php include(INCLUDE_DIR . 'header.php'); ?>
<main>
  <div class="login">
    <center>
      <form action="?page=login", method="post">
        <input class="username" placeholder="Username" name="username" id="username"></input><br>
        <input type="password" class="password" placeholder="Password" name="password" id="password"></input><br>
        <button class="submit">Login</button>
      </form>
    </center>
  </div>
</main>
<?php include(INCLUDE_DIR . 'footer.php'); ?>
