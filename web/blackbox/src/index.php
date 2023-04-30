<?php
$resource = 'home';

require './config.php';
require './util.php';

set_include_path(INCLUDE_DIR);

if(isset($_GET['page'])) {
  $resource = $_GET['page'];
  include($_GET['page'] . '.php');
} else {
  include('home.php');
}
?>
