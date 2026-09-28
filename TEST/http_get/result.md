# Result: HTTP GET

Source: Wireshark Sample Captures, `http.cap`.
https://wiki.wireshark.org/SampleCaptures

Expected: HTTP GET requests are parsed with method, URL, host, and headers.

Actual: `actual.jsonl` contains two HTTP GET events. One request has method
`GET`, host `www.ethereal.com`, URL `/download.html`, and request headers.

Result: PASS
