docker build -t test  .
docker run -it -p 80:80 -v /Users/shisharm18/Documents/projects/devops/cert-expiry-checker/python:/code test
