<!DOCTYPE html>
<html>
    <head>
        <link rel="stylesheet" href="/css/style.css">
        <title>Writeup Blog</title>
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
                    <ul class="posts">
                        <br>
                        <li class="post">
                            <span class="date">April 10, 2023</span>
                            <h3 class="post-title">
                                <a class="post-link" href="/writeups/tamuctf23/">TAMUctf 2023 Writeups</a>
                            </h3>
                            <picture>
                                <img src="/img/tamuctf.png" alt="meta" style="float: right; margin-right:50px; margin-left:50px; height:120px;" class="include_image">
                            </picture>
                            <p>
                            Collection of writeups for TAMUctf 2023. This post will be password protected until the end of the competition.
                            </p>
                        </li>
                        <br><br><br><br><br>
                        <li class="post">
                            <span class="date">Jun 18, 2022</span>
                            <h3 class="post-title">
                                <a class="post-link" href="/writeups/paper/">HackTheBox: Paper</a>
                            </h3>
                            <picture>
                                <img src="/img/paper.png" alt="meta" style="float: right; margin-right:50px; margin-left:50px; height:120px;" class="include_image">
                            </picture>
                            <p>
                            Before I get started, I just want to say that, at the time of writing (03/02/22), this is my favorite box on the platform. The box is based on The Office and has several references to the show. The user is compromised by exploiting an outdated version of WordPress as well as leaking credentials on a custom chatbot. The privilege escalation vector was using PwnKit, with the intended exploit being created by the box author. 
                            </p>
                        </li>
                        <br><br>
                        <li class="post">
                            <span class="date">Jun 11, 2022</span>
                            <h3 class="post-title">
                                <a class="post-link" href="/writeups/meta/">HackTheBox: Meta</a>
                            </h3>
                            <picture>
                                <img src="/img/meta.png" alt="meta" style="float: right; margin-right:50px; margin-left:50px; height:120px;" class="include_image">
                            </picture>
                            <p>
                            Meta was a fun medium box about vulnerabilities in common image editors. The initial foothold started with getting a reverse shell by exploiting an RCE vulnerability in ExifTool. From there, a cron job running ImageMagick is exploited to access the user. Finally, abusing neofetch with environment variables allows for root access.
                            </p>
                        </li>
                        <br><br><br><br>
                        <li class="post">
                            <span class="date">May 21, 2022 </span>
                            <h3 class="post-title">
                                <a class="post-link" href="/writeups/pandora/">HackTheBox: Pandora</a>
                            </h3>
                            <picture>
                                <img src="/img/pandora.png" alt="meta" style="float: right; margin-right:50px; margin-left:50px; height:120px;" class="include_image">
                            </picture>
                            <p>
                            Pandora is an easy box on Hack The Box. I found that, despite the classification, this box is quite difficult for an "easy" box. In this box, there are a lot of steps and a lot of exploits that will not work. I believe I tried over 10 different exploits in the user phase before finding something that works.
                           </p>
                        </li>
                        <br><br><br>
                        <li class="post">
                            <span class="date">December 30, 2021</span>
                            <h3 class="post-title">
                                <a class="post-link" href="/writeups/metactf21/">MetaCTF 2021 Writeups</a>
                            </h3>
                            <picture>
                                <img src="/img/metactf.png" alt="meta" style="float: right; margin-right:50px; margin-left:50px; height:120px;" class="include_image">
                            </picture>
                            <p>
                            Collection of writeups for MetaCTF 2021. I had a lot of fun with this competition. The writeups here are for the challenges I solved and found interesting.
                            </p>
                        </li>
                    </ul>
                </div>
            </div>
        </main>
    </body>    
</html>
