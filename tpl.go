package main

import (
	"io"
	"text/template"
)

const DEFAULT_TPL = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <link rel="stylesheet" href="https://cdn.simplecss.org/simple.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.0.0/jquery.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
    <script src="https://cdn.jsdelivr.net/npm/js-cookie@3.0.5/dist/js.cookie.min.js"></script>

    <title>Simple SSH CA</title>
    <style>
        button {
            display: block;
            margin: auto;
        }
        input {
            width: 100%;
        }
    </style>
</head>
<body>
    <input type="hidden" id="ssh-cmd" value="{{ .Command }}"/>
    <header>
        <h1>Your Ticket</h1>
    </header>
    <main>
        <section>
            <label for="identity-file-path">Identity File:</label>
            <input type="text" id="identity-file-path" value="{{ .IdentityFilePath }}"/>
            <label for="copy-target">Command:</label>
            <pre><code id="copy-target"></code></pre>
            <button id="copy-to-clipboard">Copy to clipboard</button>
        </section>
    </main>
    <script type="text/javascript">
        $(document).ready(function () {
            if(Cookies.get('_id_file_path')){
                $('identity-file-path').val(Cookies.get('_id_file_path'));
            }
            Refresh();

            $("button").click(function (event) {
                event.preventDefault();
                CopyToClipboard($('#copy-target').text(), "Value copied");
            });

            $("#identity-file-path").on('change keyup', function(){
                Refresh();
            });
        });
        function Refresh(){
            $("#copy-target").html(
                $("#ssh-cmd").val() + " > " + $("#identity-file-path").val() + "-cert.pub"
            );
            Cookies.set('_id_file_path', $("#identity-file-path").val());
        }
        function CopyToClipboard(value, notificationText) {
            var $temp = $("<input>");
            $("body").append($temp);
            $temp.val(value).select();
            document.execCommand("copy");
            $temp.remove();

            Swal.fire({
                title: 'Copied to clipboard',
                icon: 'success',
                timer: 2500,
                showConfirmButton: false,
                toast: true
            });
        }
    </script>
</body>
</html>
`

func generatePage(w io.Writer, cmd string, identityFilePath string) error {
	t, err := template.New("webpage").Parse(DEFAULT_TPL)

	if err != nil {
		return err
	}

	data := struct {
		Command          string
		IdentityFilePath string
	}{
		Command:          cmd,
		IdentityFilePath: identityFilePath,
	}

	t.Execute(w, data)

	return nil
}
