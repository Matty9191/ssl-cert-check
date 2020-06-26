docker build -t test  .
docker run -it -p 9100:9100 -v /Users/shisharm18/Documents/projects/devops/cert-expiry-checker/python:/code test
