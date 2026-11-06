# mini-burp

**A tiny HTTP proxy that shows and checks your own traffic.**

Built line by line in the [MUKULAH Dev](https://www.youtube.com/@mukulahdev) course
*Burp Suite*, part 3. Designed by Romeo Mukulah & Claude.

* Forwards plain HTTP between your browser and a lab server, and keeps a history
  like Burp's Proxy tab.
* **Hides secrets:** passwords, tokens and codes print as `***`.
* **Checks every response** for missing security headers and cookie flags, and
  warns when a login cookie or `Authorization` header travels over plain HTTP.
* **Quiet mode:** images, scripts and background polling are recorded but not
  printed; the final report counts them.
* **Safe by design:** listens only on 127.0.0.1, talks only to private lab
  addresses, refuses HTTPS tunnels, and never changes traffic.
* Python standard library only. 11 unit tests.

## Use

```bash
git clone https://github.com/mukulahdev/mini-burp.git
cd mini-burp
python3 mini_burp.py          # listening on 127.0.0.1:8081
python3 -m unittest -v
```

Point a lab browser's **HTTP** proxy at `127.0.0.1:8081`, browse a practice
app such as OWASP Juice Shop in your own lab, and press Ctrl+C for the report.

## Responsible use

For learning, and only on systems you own or have written permission to test.

## License

MIT. See [LICENSE](LICENSE).
