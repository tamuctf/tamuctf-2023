var input = document.getElementById("username")
var output = document.getElementById("output")

document.getElementById("username").addEventListener('keydown', (e) => {
    if (e.keyCode === 13) {
        let username = input.value;

        output.innerHTML = '';

        fetch('/api/chpass', {
            method: 'POST',
            body: `username=${username}`,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        })
        .then(resp => resp.json())
        .then(data => {
            output.innerHTML = 'Email sent';
        });

        input.value = '';
    }
});

