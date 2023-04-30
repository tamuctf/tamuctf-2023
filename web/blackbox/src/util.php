<?php
function db_login(string $username, string $password) {
  $db = new SQLite3(DB_FILE);
  $statement = $db->prepare('SELECT key FROM users WHERE username=:uname AND password=:passwd;');

  $statement->bindValue(':uname', $username);
  $statement->bindValue(':passwd', $password);

  return $statement->execute();
}

function try_auth(string $username, string $password) {
  $hash_password = hash('sha256', $password);
  return db_login($username, $hash_password)->fetchArray();
}

function generate_guest_token() {
  $data = array('username'=>'guest', 'user_key'=>bin2hex(random_bytes(8)), 'admin'=>false);
  return generate_token($data);
}

function generate_admin_token(string $username, string $user_key) {
  $data = array('username'=>$username, 'user_key'=>$user_key, 'admin'=>true);
  return generate_token($data);
}

function generate_token(array $data) {
  $b64json = base64_encode(json_encode($data));
  $hmac = hash('md5', SECRET_KEY . $b64json);

  return $b64json . '.' . $hmac;
}

function verify_token(string $token) { 
  $token_data = explode('.', $token);
  if(hash('md5', SECRET_KEY . $token_data[0]) == $token_data[1]) {
    return true;
  }
  return false;
}

function is_admin(string $token) {
  if(verify_token($token)) {
    $db = new SQLite3(DB_FILE);

    $data = json_decode(base64_decode(explode('.', $token)[0]), TRUE);
    $username = $data['username'];
    $user_key = $data['user_key'];
    $admin = $data['admin'];

    $statement = $db->prepare('SELECT * FROM users WHERE username=:uname AND key=:ukey;');
    $statement->bindValue(':uname', $username);
    $statement->bindValue(':ukey', $user_key);
    $result = $statement->execute();

    if($result != false && $result->fetchArray() != false && $admin == true) {
      return true;
    }
    return false;
  }
}
?>
