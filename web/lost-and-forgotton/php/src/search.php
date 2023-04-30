<?php
$anything = true;
$servername = "db";
$username = "ro_user";
$password = "r0us3rp4SSw0Rd1123492482!2@#";
$dbname = "writeups";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if(isset($_POST['query'])) {
    $search_query = $_POST['query'];
} else {
    $anything = false;
}

if($anything == true) {
    #$sql = "SELECT title, postdate, descr, imgloc, artloc, passwd FROM writeups.articles WHERE title LIKE '%{$search_query}%';";
    $sql = "SELECT * FROM writeups.articles WHERE title LIKE '%{$search_query}%';";
    $result = $conn->query($sql);

    
    $conn->close();
}
?>

<!DOCTYPE html>
<html>
    <head>
        <link rel="stylesheet" href="/css/style.css">
        <title>Search Results</title>
    </head>
    <body>
        <header class="site-header">
            <div class="header-content">
                <a class="site-title" rel="author" href="/">Writeups</a>
                <nav class="site-nav">
                    <a class="page-link" href="https://github.com/tamuctf">
                        <img class="icon" src="/img/github.png" alt>
                        Github
                    </a>
                </nav>
            </div>
        </header>
        <main class="page-content">
            <div class="wrapper">
                <div class="home">
                    <form action="/search.php" method="POST">
                        <input class="search-bar" type="text" name="query" id="query" placeholder="Search">
                    </form>
                    <h2 class="posts-head">Posts</h2>
                    <?php
                    $results = array();
                    if (!empty($result->num_rows) && $result->num_rows > 0) {
                        while($row = $result->fetch_assoc()) {
                            array_push($results, "<ul class='posts'><br><li class='post'><span class='date'> {$row["postdate"]}</span><h3 class='post-title'><a class='post-link' href='{$row["artloc"]}'>{$row["title"]}</a></h3><picture><img src='{$row["imgloc"]}' alt='meta' style='float: right; margin-right:50px; margin-left:50px; height:120px;' class='include_image'></picture><p>{$row["descr"]}</p></li></ul>");
                        }
                        for($i = count($results) - 1; $i >= 0; $i--) {
                            echo $results[$i];
                        }
                    } else {
                        echo "0 Results";
                    }
                    ?>
                </div>
            </div>
        </main>
    </body>
</html>