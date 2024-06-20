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
    <title>Simple SSH CA</title>
</head>
<body>
    <main>
        <pre><code>{{ .Command }}</code></pre>
        <center><a class="button" href="#">Copy to clipboard</a></center>
    </main>
</body>
</html>
`

func generatePage(w io.Writer, cmd string) error {
	t, err := template.New("webpage").Parse(DEFAULT_TPL)

	if err != nil {
		return err
	}

	data := struct {
		Command string
	}{
		Command: cmd,
	}

	t.Execute(w, data)

	return nil
}
