#### Test run:

- `xcaddy run`
- `curl localhost:7070/api/test -H "Authorization: Bearer mytoken" -i`
- `wrk -t4 -c100 -d3s "http://localhost:7070/api/test" -H "Authorization: Bearer mytoken"`